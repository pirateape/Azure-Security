# Run Prowler Scan for Azure
# Note: Requires Prowler to be installed (pip install prowler)

# Scan storage, network, and IAM services
prowler azure --services storage network iam --output-directory ./Reports/Infra

# Key Checks to Review:
# - Public Exposure: Storage blobs with "Public Access" enabled.
# - Management Ports: RDP/SSH ports (3389/22) open to 0.0.0.0/0.
# - RBAC: "Owner" permissions assigned to excessively large groups.
