import boto3
import json
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    """
    Lambda function to tag security groups that allow traffic from 0.0.0.0/0
    """
    
    # Initialize EC2 client
    ec2_client = boto3.client('ec2')
    
    # Tag to apply to permissive security groups
    tag_key = 'notification'
    tag_value = 'mark for deletion'
    
    results = {
        'tagged_security_groups': [],
        'errors': [],
        'total_processed': 0
    }
    
    try:
        # Get all security groups
        paginator = ec2_client.get_paginator('describe_security_groups')
        
        for page in paginator.paginate():
            for sg in page['SecurityGroups']:
                results['total_processed'] += 1
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                
                # Check if security group has permissive rules
                is_permissive = check_permissive_rules(sg)
                
                if is_permissive:
                    try:
                        # Check if tag already exists
                        existing_tags = {tag['Key']: tag['Value'] for tag in sg.get('Tags', [])}
                        
                        if tag_key not in existing_tags:
                            # Apply tag to the security group
                            ec2_client.create_tags(
                                Resources=[sg_id],
                                Tags=[
                                    {
                                        'Key': tag_key,
                                        'Value': tag_value
                                    }
                                ]
                            )
                            
                            results['tagged_security_groups'].append({
                                'security_group_id': sg_id,
                                'security_group_name': sg_name,
                                'action': 'tagged'
                            })
                            
                            print(f"Tagged security group {sg_id} ({sg_name}) for deletion due to permissive rules")
                        else:
                            results['tagged_security_groups'].append({
                                'security_group_id': sg_id,
                                'security_group_name': sg_name,
                                'action': 'already_tagged'
                            })
                            
                            print(f"Security group {sg_id} ({sg_name}) already marked for deletion")
                            
                    except ClientError as e:
                        error_msg = f"Failed to tag security group {sg_id}: {str(e)}"
                        results['errors'].append(error_msg)
                        print(error_msg)
    
    except ClientError as e:
        error_msg = f"Failed to describe security groups: {str(e)}"
        results['errors'].append(error_msg)
        print(error_msg)
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Function execution failed',
                'error': error_msg
            })
        }
    
    # Prepare response
    response_body = {
        'message': f'Successfully processed {results["total_processed"]} security groups',
        'tagged_count': len([sg for sg in results['tagged_security_groups'] if sg['action'] == 'tagged']),
        'already_tagged_count': len([sg for sg in results['tagged_security_groups'] if sg['action'] == 'already_tagged']),
        'tagged_security_groups': results['tagged_security_groups'],
        'errors': results['errors']
    }
    
    print(f"Function completed. Marked {response_body['tagged_count']} new security groups for deletion")
    
    return {
        'statusCode': 200,
        'body': json.dumps(response_body, default=str)
    }


def check_permissive_rules(security_group):
    """
    Check if a security group has rules allowing traffic from 0.0.0.0/0
    
    Args:
        security_group (dict): Security group object from AWS API
        
    Returns:
        bool: True if the security group has permissive rules, False otherwise
    """
    
    # Check inbound rules
    for rule in security_group.get('IpPermissions', []):
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                return True
        
        # Also check IPv6 ranges
        for ipv6_range in rule.get('Ipv6Ranges', []):
            if ipv6_range.get('CidrIpv6') == '::/0':
                return True
    
    # Check outbound rules (though these are less commonly restricted)
    for rule in security_group.get('IpPermissionsEgress', []):
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                return True
        
        # Also check IPv6 ranges
        for ipv6_range in rule.get('Ipv6Ranges', []):
            if ipv6_range.get('CidrIpv6') == '::/0':
                return True
    
    return False


def get_rule_details(security_group):
    """
    Helper function to get detailed information about permissive rules
    (Optional - can be used for more detailed logging)
    
    Args:
        security_group (dict): Security group object from AWS API
        
    Returns:
        list: List of permissive rules found
    """
    
    permissive_rules = []
    
    # Check inbound rules
    for rule in security_group.get('IpPermissions', []):
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                permissive_rules.append({
                    'direction': 'inbound',
                    'protocol': rule.get('IpProtocol'),
                    'from_port': rule.get('FromPort'),
                    'to_port': rule.get('ToPort'),
                    'cidr': ip_range.get('CidrIp')
                })
    
    # Check outbound rules
    for rule in security_group.get('IpPermissionsEgress', []):
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                permissive_rules.append({
                    'direction': 'outbound',
                    'protocol': rule.get('IpProtocol'),
                    'from_port': rule.get('FromPort'),
                    'to_port': rule.get('ToPort'),
                    'cidr': ip_range.get('CidrIp')
                })
    
    return permissive_rules