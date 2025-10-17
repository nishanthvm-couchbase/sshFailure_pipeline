import paramiko
import os
from couchbase.cluster import Cluster
from couchbase.auth import PasswordAuthenticator
from couchbase.options import ClusterOptions
import logging
from datetime import timedelta

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_cluster_data():
    try:
        cluster_ip = "172.23.105.178"
        username = os.getenv('CLUSTER_USERNAME')
        password = os.getenv('CLUSTER_PASSWORD')
        
        if not all([cluster_ip, username, password]):
            raise ValueError("Missing required environment variables: CLUSTER_IP, CLUSTER_USERNAME, CLUSTER_PASSWORD")
        
        logger.info(f"Connecting to cluster: {cluster_ip}")
        
        cluster = Cluster(f'couchbase://{cluster_ip}', ClusterOptions(
            PasswordAuthenticator(username, password)
        ))
        
        cluster.wait_until_ready(timeout=timedelta(seconds=5))
        
        query = """
        SELECT META().id AS ip,
               origin AS host
        FROM `QE-server-pool`
        WHERE state = "sshFailed"
            AND os != "windows"
            AND (poolId = "regression" or "regression" in poolId) LIMIT 1
        """
        
        logger.info("Executing cluster query...")
        result = cluster.query(query)
        
        data = []
        for row in result:
            data.append({
                "ip": row["ip"],
                "host": row["host"]
            })
        
        logger.info(f"Retrieved {len(data)} VMs from cluster")
        return data
        
    except Exception as e:
        logger.error(f"Error querying cluster: {e}")
        raise

def check_ssh_connectivity(data):
    failed_hosts = []
    working_hosts = []
    
    ssh_username = os.getenv('SSH_USERNAME')
    ssh_password = os.getenv('SSH_PASSWORD')
    
    logger.info(f"Starting SSH connectivity check for {len(data)} VMs...")
    
    for entry in data:
        host = entry.get("host")
        ip = entry.get("ip")
        
        logger.info(f"Checking SSH for {host} ({ip})...")
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(ip, username=ssh_username, password=ssh_password, timeout=5)
            logger.info(f"SSH successful for {host} ({ip})")
            working_hosts.append({"host": host, "ip": ip})
            ssh.close()
        except Exception as e:
            logger.warning(f"SSH failed for {host} ({ip}): {e}")
            failed_hosts.append({"host": host, "ip": ip})
    
    logger.info(f"SSH check completed! Working: {len(working_hosts)}, Failed: {len(failed_hosts)}")
    return working_hosts, failed_hosts

def update_vm_states_to_available(working_hosts):
    logger.info(f"Updating {len(working_hosts)} VMs to available state")
    
    if not working_hosts:
        logger.info("No working hosts to update")
        return
    
    try:
        cluster_ip = "172.23.105.178"
        username = os.getenv('CLUSTER_USERNAME')
        password = os.getenv('CLUSTER_PASSWORD')
        
        cluster = Cluster(f'couchbase://{cluster_ip}', ClusterOptions(
            PasswordAuthenticator(username, password)
        ))
        
        cluster.wait_until_ready(timeout=timedelta(seconds=5))
        
        for vm in working_hosts:
            update_query = f"""
            UPDATE `QE-server-pool`
            SET state = "available"
            WHERE META().id = "{vm['ip']}"
            """
            cluster.query(update_query)
            logger.info(f"Updated {vm['host']} ({vm['ip']}) to available")
            
    except Exception as e:
        logger.error(f"Error updating VM states: {e}")
        raise

def create_email_content(failed_hosts, working_hosts):
    """Create beautiful formatted email content"""
    if not failed_hosts:
        content = f"""
╔══════════════════════════════════════════════════════════════╗
║                    SSH CONNECTIVITY REPORT                   ║
╠══════════════════════════════════════════════════════════════╣
║ Status: ✅ ALL VMs ARE WORKING                               ║
║ Working VMs: {len(working_hosts)}                            ║
║ Failed VMs: 0                                                ║
╚══════════════════════════════════════════════════════════════╝

All SSH connections are working properly. No action required.
"""
    else:
        content = f"""
╔══════════════════════════════════════════════════════════════╗
║                 SSH CONNECTION FAILURES                      ║
╠══════════════════════════════════════════════════════════════╣
║ Status: ❌ {len(failed_hosts)} VM(S) HAVE SSH ISSUES         ║
║ Working VMs: {len(working_hosts)}                            ║
║ Failed VMs: {len(failed_hosts)}                              ║
╚══════════════════════════════════════════════════════════════╝

🔴 FAILED VMs (SSH connectivity broken):
"""
        for i, vm in enumerate(failed_hosts, 1):
            content += f"   {i}. {vm['host']} ({vm['ip']})\n"
        
        content += f"""
📊 SUMMARY:
   • Total VMs checked: {len(failed_hosts) + len(working_hosts)}
   • Working VMs: {len(working_hosts)}
   • Failed VMs: {len(failed_hosts)}
   
⚠️  ACTION REQUIRED:
   Please investigate and resolve the SSH connectivity issues for the failed VMs listed above.
"""
    
    return content

def log_failed_hosts(failed_hosts, working_hosts):
    """Log failed hosts and create email content"""
    email_content = create_email_content(failed_hosts, working_hosts)
    
    # Print beautiful formatted content to stdout for Jenkins
    print(email_content)
    
    # Also log for console output
    if not failed_hosts:
        logger.info("All VMs are working - no SSH issues detected")
    else:
        logger.info(f"SSH Connection Failures - {len(failed_hosts)} VMs Affected")
        logger.info("SSH connectivity is broken for the following VMs:")
        for vm in failed_hosts:
            logger.info(f"• {vm['host']} ({vm['ip']})")
        logger.info(f"Total affected VMs: {len(failed_hosts)}")
        logger.info("Please investigate and resolve the SSH connectivity issues.")
    
    return email_content


def main():
    try:
        logger.info("Starting SSH Fail Reporter workflow...")
   
        logger.info("Querying cluster for SSH failed VMs...")
        cluster_data = get_cluster_data()
        
        if not cluster_data:
            logger.warning("No VMs found in cluster query")
            return
        
        logger.info("Checking SSH connectivity...")
        working_hosts, failed_hosts = check_ssh_connectivity(cluster_data)
        
        logger.info("Updating working VMs to available state...")
        update_vm_states_to_available(working_hosts)
        
        logger.info("Logging failed hosts...")
        email_content = log_failed_hosts(failed_hosts, working_hosts)
        
        # Export email content to environment variable for Jenkins
        os.environ['SSH_REPORT_CONTENT'] = email_content
        
        
        logger.info("SSH Fail Reporter workflow completed successfully!")
        logger.info(f"Summary: {len(working_hosts)} working VMs, {len(failed_hosts)} failed VMs")
        
    except Exception as e:
        logger.error(f"Workflow failed: {e}")
        raise

if __name__ == "__main__":
    main()
