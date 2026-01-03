"""
GKE Service for managing Frappe site provisioning in Kubernetes.
"""

import logging
from typing import Optional
from kubernetes import client, config
from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)


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
            use_in_cluster: Whether running inside a cluster (True for Cloud Run)
        """
        self.namespace = namespace
        self.frappe_image = frappe_image

        try:
            if use_in_cluster:
                config.load_incluster_config()
            else:
                config.load_kube_config()

            self.core_v1 = client.CoreV1Api()
            self.batch_v1 = client.BatchV1Api()
            self._connected = True
            logger.info("Successfully connected to Kubernetes cluster")
        except Exception as e:
            logger.warning(f"Could not connect to Kubernetes cluster: {e}")
            self._connected = False

    @property
    def is_connected(self) -> bool:
        """Check if connected to Kubernetes cluster."""
        return self._connected

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
                                    bench new-site {site_name} \
                                        --db-root-password $DB_ROOT_PASSWORD \
                                        --db-host $DB_HOST \
                                        --admin-password $ADMIN_PASSWORD

                                    # Install apps
                                    bench --site {site_name} install-app kairos

                                    # Add admin user
                                    bench --site {site_name} add-user {admin_email} \
                                        --first-name "{organization}" \
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
            self.batch_v1.create_namespaced_job(namespace=self.namespace, body=job)
            logger.info(f"Created provisioning job: {job_name}")
            return {"success": True, "job_name": job_name}
        except ApiException as e:
            logger.error(f"Failed to create provisioning job: {e}")
            return {"success": False, "error": str(e)}

    async def get_job_status(self, job_name: str) -> dict:
        """
        Get the status of a provisioning job.

        Args:
            job_name: Name of the Kubernetes job

        Returns:
            dict with status information
        """
        if not self._connected:
            return {"success": False, "error": "Not connected to Kubernetes"}

        try:
            job = self.batch_v1.read_namespaced_job(
                name=job_name, namespace=self.namespace
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
                return {"success": False, "error": "Job not found"}
            logger.error(f"Failed to get job status: {e}")
            return {"success": False, "error": str(e)}

    async def create_tenant_secret(
        self, tenant_id: str, admin_password: str
    ) -> dict:
        """
        Create a Kubernetes secret for tenant credentials.

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
            self.core_v1.create_namespaced_secret(
                namespace=self.namespace, body=secret
            )
            logger.info(f"Created tenant secret: {secret_name}")
            return {"success": True, "secret_name": secret_name}
        except ApiException as e:
            logger.error(f"Failed to create tenant secret: {e}")
            return {"success": False, "error": str(e)}

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
            self.core_v1.delete_namespaced_secret(
                name=secret_name, namespace=self.namespace
            )
        except ApiException as e:
            if e.status != 404:
                errors.append(f"Failed to delete secret: {e}")

        # Delete any provisioning jobs
        try:
            job_name = f"provision-{tenant_id[:8]}-{subdomain}"
            self.batch_v1.delete_namespaced_job(
                name=job_name,
                namespace=self.namespace,
                body=client.V1DeleteOptions(propagation_policy="Foreground"),
            )
        except ApiException as e:
            if e.status != 404:
                errors.append(f"Failed to delete job: {e}")

        if errors:
            return {"success": False, "errors": errors}
        return {"success": True}
