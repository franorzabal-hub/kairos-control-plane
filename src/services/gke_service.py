"""
GKE Service for managing Frappe site provisioning in Kubernetes.
"""

import asyncio
import base64
import functools
import logging
import os
import shlex
import tempfile
from typing import Optional, Callable, TypeVar, Any

import google.auth
import google.auth.transport.requests
from google.cloud import container_v1
from kubernetes import client, config
from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)

# GKE cluster configuration from environment
GKE_PROJECT = os.environ.get("GKE_PROJECT", "kairos-escuela-app")
GKE_LOCATION = os.environ.get("GKE_LOCATION", "us-central1")
GKE_CLUSTER = os.environ.get("GKE_CLUSTER", "kairos-cluster-dev")

T = TypeVar("T")


def sanitize_for_shell(value: str) -> str:
    """
    Sanitize a string value for safe use in shell commands.

    Uses shlex.quote to properly escape the value, preventing
    command injection attacks.

    Args:
        value: The string value to sanitize

    Returns:
        A shell-safe quoted string
    """
    return shlex.quote(value)


def retry_with_backoff(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
) -> Callable:
    """
    Decorator that adds retry logic with exponential backoff to async functions.

    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay between retries in seconds
        max_delay: Maximum delay between retries in seconds

    Returns:
        Decorated function with retry logic
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except ApiException as e:
                    last_exception = e
                    # Don't retry on client errors (4xx) except for rate limiting (429)
                    if 400 <= e.status < 500 and e.status != 429:
                        raise
                    if attempt < max_retries:
                        delay = min(base_delay * (2**attempt), max_delay)
                        logger.warning(
                            f"Retry {attempt + 1}/{max_retries} for {func.__name__} "
                            f"after {delay:.1f}s delay. Error: {e.reason}"
                        )
                        await asyncio.sleep(delay)
                    else:
                        raise
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries:
                        delay = min(base_delay * (2**attempt), max_delay)
                        logger.warning(
                            f"Retry {attempt + 1}/{max_retries} for {func.__name__} "
                            f"after {delay:.1f}s delay. Error: {str(e)}"
                        )
                        await asyncio.sleep(delay)
                    else:
                        raise
            raise last_exception

        return wrapper

    return decorator


class GKEService:
    """
    Service to interact with GKE for provisioning Frappe tenant sites.

    This service handles:
    - Creating Kubernetes jobs for site provisioning
    - Checking provisioning job status
    - Managing site-specific resources
    """

    def __init__(
        self,
        namespace: str = "frappe",
        frappe_image: str = "frappe/frappe-worker:v15",
        use_in_cluster: bool = True,
    ):
        """
        Initialize the GKE service.

        Args:
            namespace: Kubernetes namespace for Frappe workloads
            frappe_image: Docker image for Frappe worker
            use_in_cluster: Whether running inside a cluster (True for in-cluster, False for Cloud Run/external)
        """
        self.namespace = namespace
        self.frappe_image = frappe_image

        try:
            if use_in_cluster:
                config.load_incluster_config()
                logger.info("Loaded in-cluster Kubernetes config")
            else:
                # Try to connect to GKE from outside the cluster (Cloud Run)
                self._configure_gke_client()
                logger.info("Connected to GKE cluster from Cloud Run")

            self.core_v1 = client.CoreV1Api()
            self.batch_v1 = client.BatchV1Api()
            self._connected = True
            logger.info("Successfully connected to Kubernetes cluster")
        except Exception as e:
            logger.warning(f"Could not connect to Kubernetes cluster: {e}")
            self._connected = False

    def _configure_gke_client(self):
        """
        Configure Kubernetes client to connect to GKE from Cloud Run.

        Uses Application Default Credentials (ADC) which automatically
        uses the Cloud Run service account.
        """
        # Get credentials using ADC (Application Default Credentials)
        credentials, project = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )

        # Refresh credentials to get access token
        auth_req = google.auth.transport.requests.Request()
        credentials.refresh(auth_req)

        # Get cluster info from GKE API
        cluster_manager = container_v1.ClusterManagerClient(credentials=credentials)
        cluster_name = f"projects/{GKE_PROJECT}/locations/{GKE_LOCATION}/clusters/{GKE_CLUSTER}"

        cluster = cluster_manager.get_cluster(name=cluster_name)

        # Configure kubernetes client
        configuration = client.Configuration()
        configuration.host = f"https://{cluster.endpoint}"

        # Use the access token for authentication
        configuration.api_key = {"authorization": f"Bearer {credentials.token}"}

        # Set up CA certificate
        ca_cert = base64.b64decode(cluster.master_auth.cluster_ca_certificate)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as ca_file:
            ca_file.write(ca_cert)
            configuration.ssl_ca_cert = ca_file.name

        # Set this as the default configuration
        client.Configuration.set_default(configuration)

        logger.info(f"Configured GKE client for cluster: {GKE_CLUSTER}")

    @property
    def is_connected(self) -> bool:
        """Check if connected to Kubernetes cluster."""
        return self._connected

    async def _run_in_executor(self, func: Callable, *args, **kwargs) -> Any:
        """
        Run a synchronous function in an executor to make it non-blocking.

        Args:
            func: The synchronous function to run
            *args: Positional arguments to pass to the function
            **kwargs: Keyword arguments to pass to the function

        Returns:
            The result of the function call
        """
        loop = asyncio.get_event_loop()
        partial_func = functools.partial(func, *args, **kwargs)
        return await loop.run_in_executor(None, partial_func)

    async def check_health(self) -> bool:
        """
        Check if the Kubernetes cluster connection is healthy.

        Attempts to list namespaces with a limit of 1 to verify connectivity.

        Returns:
            True if the cluster is reachable, False otherwise
        """
        if not self._connected:
            return False

        try:
            await self._run_in_executor(
                self.core_v1.list_namespace, limit=1
            )
            return True
        except ApiException as e:
            logger.error(
                f"Health check failed - API error: {e.reason}. "
                f"Status: {e.status}. Body: {e.body}"
            )
            return False
        except Exception as e:
            logger.error(f"Health check failed - unexpected error: {str(e)}")
            return False

    async def create_site_provisioning_job(
        self,
        tenant_id: str,
        subdomain: str,
        organization: str,
        admin_email: str,
        base_domain: str,
    ) -> dict:
        """
        Create a Kubernetes job to provision a new Frappe site.

        Args:
            tenant_id: Unique tenant identifier
            subdomain: Tenant subdomain
            organization: Organization name
            admin_email: Admin email address
            base_domain: Base domain for sites

        Returns:
            dict with job_name and status
        """
        if not self._connected:
            return {"success": False, "error": "Not connected to Kubernetes"}

        site_name = f"{subdomain}.{base_domain}"
        job_name = f"provision-{tenant_id[:8]}-{subdomain}"

        # Sanitize user inputs for shell command safety
        safe_site_name = sanitize_for_shell(site_name)
        safe_organization = sanitize_for_shell(organization)
        safe_admin_email = sanitize_for_shell(admin_email)

        # Define the job specification
        job = client.V1Job(
            api_version="batch/v1",
            kind="Job",
            metadata=client.V1ObjectMeta(
                name=job_name,
                namespace=self.namespace,
                labels={
                    "app": "frappe-provisioner",
                    "tenant-id": tenant_id,
                    "subdomain": subdomain,
                },
            ),
            spec=client.V1JobSpec(
                ttl_seconds_after_finished=3600,  # Clean up after 1 hour
                backoff_limit=2,
                template=client.V1PodTemplateSpec(
                    spec=client.V1PodSpec(
                        restart_policy="Never",
                        containers=[
                            client.V1Container(
                                name="provision",
                                image=self.frappe_image,
                                command=["/bin/bash", "-c"],
                                args=[
                                    f"""
                                    set -e
                                    cd /home/frappe/frappe-bench

                                    # Create new site
                                    bench new-site {safe_site_name} \
                                        --db-root-password $DB_ROOT_PASSWORD \
                                        --db-host $DB_HOST \
                                        --admin-password $ADMIN_PASSWORD

                                    # Install apps
                                    bench --site {safe_site_name} install-app kairos

                                    # Add admin user
                                    bench --site {safe_site_name} add-user {safe_admin_email} \
                                        --first-name {safe_organization} \
                                        --password $ADMIN_PASSWORD \
                                        --user-type "System User" \
                                        --add-role "System Manager"

                                    echo "Site provisioning completed successfully"
                                    """
                                ],
                                env=[
                                    client.V1EnvVar(
                                        name="DB_ROOT_PASSWORD",
                                        value_from=client.V1EnvVarSource(
                                            secret_key_ref=client.V1SecretKeySelector(
                                                name="frappe-db-credentials",
                                                key="root-password",
                                            )
                                        ),
                                    ),
                                    client.V1EnvVar(
                                        name="DB_HOST",
                                        value_from=client.V1EnvVarSource(
                                            config_map_key_ref=client.V1ConfigMapKeySelector(
                                                name="frappe-config",
                                                key="db-host",
                                            )
                                        ),
                                    ),
                                    client.V1EnvVar(
                                        name="ADMIN_PASSWORD",
                                        value_from=client.V1EnvVarSource(
                                            secret_key_ref=client.V1SecretKeySelector(
                                                name=f"tenant-{tenant_id[:8]}-credentials",
                                                key="admin-password",
                                            )
                                        ),
                                    ),
                                ],
                                volume_mounts=[
                                    client.V1VolumeMount(
                                        name="sites",
                                        mount_path="/home/frappe/frappe-bench/sites",
                                    )
                                ],
                            )
                        ],
                        volumes=[
                            client.V1Volume(
                                name="sites",
                                persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                                    claim_name="frappe-sites-pvc"
                                ),
                            )
                        ],
                    )
                ),
            ),
        )

        try:
            await self._run_in_executor(
                self.batch_v1.create_namespaced_job,
                namespace=self.namespace,
                body=job,
            )
            logger.info(f"Created provisioning job: {job_name}")
            return {"success": True, "job_name": job_name}
        except ApiException as e:
            error_body = e.body if hasattr(e, "body") else "No response body"
            logger.error(
                f"Failed to create provisioning job '{job_name}': "
                f"Status={e.status}, Reason={e.reason}, Body={error_body}"
            )
            return {
                "success": False,
                "error": f"Kubernetes API error: {e.reason}",
                "status_code": e.status,
                "details": error_body,
            }

    @retry_with_backoff(max_retries=3, base_delay=1.0, max_delay=30.0)
    async def get_job_status(self, job_name: str) -> dict:
        """
        Get the status of a provisioning job.

        This method includes retry logic with exponential backoff for resilience.

        Args:
            job_name: Name of the Kubernetes job

        Returns:
            dict with status information
        """
        if not self._connected:
            return {"success": False, "error": "Not connected to Kubernetes"}

        try:
            job = await self._run_in_executor(
                self.batch_v1.read_namespaced_job,
                name=job_name,
                namespace=self.namespace,
            )

            status = "unknown"
            if job.status.succeeded:
                status = "completed"
            elif job.status.failed:
                status = "failed"
            elif job.status.active:
                status = "running"
            else:
                status = "pending"

            return {
                "success": True,
                "status": status,
                "active": job.status.active or 0,
                "succeeded": job.status.succeeded or 0,
                "failed": job.status.failed or 0,
            }
        except ApiException as e:
            if e.status == 404:
                return {
                    "success": False,
                    "error": f"Job '{job_name}' not found in namespace '{self.namespace}'",
                }
            error_body = e.body if hasattr(e, "body") else "No response body"
            logger.error(
                f"Failed to get job status for '{job_name}': "
                f"Status={e.status}, Reason={e.reason}, Body={error_body}"
            )
            return {
                "success": False,
                "error": f"Kubernetes API error: {e.reason}",
                "status_code": e.status,
                "details": error_body,
            }

    @retry_with_backoff(max_retries=3, base_delay=1.0, max_delay=30.0)
    async def create_tenant_secret(
        self, tenant_id: str, admin_password: str
    ) -> dict:
        """
        Create a Kubernetes secret for tenant credentials.

        This method includes retry logic with exponential backoff for resilience.

        Args:
            tenant_id: Unique tenant identifier
            admin_password: Admin password for the tenant

        Returns:
            dict with success status
        """
        if not self._connected:
            return {"success": False, "error": "Not connected to Kubernetes"}

        secret_name = f"tenant-{tenant_id[:8]}-credentials"

        secret = client.V1Secret(
            api_version="v1",
            kind="Secret",
            metadata=client.V1ObjectMeta(
                name=secret_name,
                namespace=self.namespace,
                labels={"tenant-id": tenant_id},
            ),
            type="Opaque",
            string_data={"admin-password": admin_password},
        )

        try:
            await self._run_in_executor(
                self.core_v1.create_namespaced_secret,
                namespace=self.namespace,
                body=secret,
            )
            logger.info(f"Created tenant secret: {secret_name}")
            return {"success": True, "secret_name": secret_name}
        except ApiException as e:
            error_body = e.body if hasattr(e, "body") else "No response body"
            logger.error(
                f"Failed to create tenant secret '{secret_name}': "
                f"Status={e.status}, Reason={e.reason}, Body={error_body}"
            )
            return {
                "success": False,
                "error": f"Kubernetes API error: {e.reason}",
                "status_code": e.status,
                "details": error_body,
            }

    async def delete_tenant_resources(self, tenant_id: str, subdomain: str) -> dict:
        """
        Delete all Kubernetes resources for a tenant.

        Args:
            tenant_id: Unique tenant identifier
            subdomain: Tenant subdomain

        Returns:
            dict with success status
        """
        if not self._connected:
            return {"success": False, "error": "Not connected to Kubernetes"}

        errors = []

        # Delete secret
        try:
            secret_name = f"tenant-{tenant_id[:8]}-credentials"
            await self._run_in_executor(
                self.core_v1.delete_namespaced_secret,
                name=secret_name,
                namespace=self.namespace,
            )
        except ApiException as e:
            if e.status != 404:
                error_body = e.body if hasattr(e, "body") else "No response body"
                errors.append(
                    f"Failed to delete secret: {e.reason} (Status: {e.status}, Body: {error_body})"
                )

        # Delete any provisioning jobs
        try:
            job_name = f"provision-{tenant_id[:8]}-{subdomain}"
            await self._run_in_executor(
                self.batch_v1.delete_namespaced_job,
                name=job_name,
                namespace=self.namespace,
                body=client.V1DeleteOptions(propagation_policy="Foreground"),
            )
        except ApiException as e:
            if e.status != 404:
                error_body = e.body if hasattr(e, "body") else "No response body"
                errors.append(
                    f"Failed to delete job: {e.reason} (Status: {e.status}, Body: {error_body})"
                )

        if errors:
            return {"success": False, "errors": errors}
        return {"success": True}
