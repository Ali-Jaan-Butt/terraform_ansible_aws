# EC2 instance resource definition
resource "aws_instance" "automation_win_vm" {
    ami                    = "ami-0fc682b2a42e57ca2" # Specify the Windows AMI ID here
    instance_type          = "t2.micro" # Set the desired instance type here
    key_name               = "automation_vm_key" # Replace with your existing EC2 key pair
    subnet_id              = "subnet-0b108097e0b19995b"  # Replace with your desired subnet ID
    vpc_security_group_ids = ["sg-062400d2c5c023712"]  # Replace with the security group ID for Windows instances
    count                  = 1
    get_password_data = true
    # Tags for the instance (optional but recommended)
    tags = {
        Name = "AutomationInstance"
        # Add more tags as needed
    }

# User data to configure the instance (optional)
# You can use this to run scripts during instance initialization.

user_data = <<-EOF
<powershell>
    # Enable PowerShell remoting
    Enable-PSRemoting -Force

    # Set WinRM service startup type to automatic
    Set-Service WinRM -StartupType 'Automatic'

    # Configure WinRM Service
    Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true
    Set-Item -Path 'WSMan:\localhost\Service\AllowUnencrypted' -Value $true
    Set-Item -Path 'WSMan:\localhost\Service\Auth\Basic' -Value $true
    Set-Item -Path 'WSMan:\localhost\Service\Auth\CredSSP' -Value $true

    # Create a self-signed certificate and set up an HTTPS listener
    $cert = New-SelfSignedCertificate -DnsName $(Invoke-RestMethod -Uri http://169.254.169.254/latest/meta-data/public-hostname) -CertStoreLocation "cert:\LocalMachine\My"
    winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$(Invoke-RestMethod -Uri http://169.254.169.254/latest/meta-data/public-hostname)`";CertificateThumbprint=`"$($cert.Thumbprint)`"}"

    # Create a firewall rule to allow WinRM HTTPS inbound
    New-NetFirewallRule -DisplayName "Allow WinRM HTTPS" -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Allow

    # Configure TrustedHosts
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

    # Set LocalAccountTokenFilterPolicy
    New-ItemProperty -Name LocalAccountTokenFilterPolicy -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -PropertyType DWord -Value 1 -Force

    # Set Execution Policy to Unrestricted
    Set-ExecutionPolicy Unrestricted -Force

    # Restart the WinRM service
    Restart-Service WinRM

    # List the WinRM listeners
    winrm enumerate winrm/config/Listener
</powershell>
EOF
}

#resource "aws_ec2_instance_state" "automation_win_vm" {
#    count       = 2
#    instance_id = aws_instance.automation_win_vm[count.index].id
#    state       = "running" # "stopped" or "running"
#}

# Output the public IP address of the instance
output "public_ipv4_address" {
    description = "Public IPv4 address"
    value = [for instance in aws_instance.automation_win_vm : instance.public_ip]
}

# Output the password of the instance
output "password" {
    description = "Password"
    value = [for instance in aws_instance.automation_win_vm : "${rsadecrypt(instance.password_data, file("/Users/hassanazhar/Python/bitbrowser_terraform_ansible_aws/automation_vm_key.pem"))}"]
}