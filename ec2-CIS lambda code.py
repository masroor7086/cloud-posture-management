import boto3
import os
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def tag_instance(instance_id, employee_id, tag_name='EmployeeID'):
    """
    Add employee ID tag to an EC2 instance
    
    Args:
        instance_id (str): The ID of the EC2 instance
        employee_id (str): The employee ID to use as tag value
        tag_name (str): The tag key to use (default: 'EmployeeID')
    
    Returns:
        bool: True if tagging was successful, False otherwise
    """
    try:
        ec2_client = boto3.client('ec2')
        ec2_client.create_tags(
            Resources=[instance_id],
            Tags=[
                {
                    'Key': tag_name,
                    'Value': employee_id
                }
            ]
        )
        logger.info(f"Successfully tagged instance {instance_id} with {tag_name}={employee_id}")
        return True
    except Exception as e:
        logger.error(f"Error tagging instance {instance_id}: {str(e)}")
        return False

def lambda_handler(event, context):
    """
    Lambda function to stop EC2 instances that don't have any tags.
    Only instances with at least one tag should be running.
    """
    # Set up the EC2 client
    ec2_client = boto3.client('ec2')
    
    try:
        # Get all running and pending EC2 instances (we only want to stop running ones)
        response = ec2_client.describe_instances(
            Filters=[
                {
                    'Name': 'instance-state-name',
                    'Values': ['running', 'pending']
                }
            ]
        )
        
        # Lists to store instance information
        instances_to_stop = []
        valid_instances = []
        
        # Check each instance for tags
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                instance_state = instance['State']['Name']
                
                # Check if instance has name and tags
                has_name = False
                has_other_tags = False
                instance_name = None
                tag_details = []
                
                # Check for Tags key and if it contains any tags
                if 'Tags' in instance and instance['Tags']:
                    for tag in instance['Tags']:
                        # Check if tag has both key and non-empty value
                        if tag.get('Key') and tag.get('Value') and tag['Value'].strip():
                            tag_details.append(f"{tag['Key']}={tag['Value']}")
                            
                            # Check if this is the Name tag
                            if tag['Key'].lower() == 'name':
                                has_name = True
                                instance_name = tag['Value']
                            else:
                                # Any other tag (not Name)
                                has_other_tags = True
                
                # Instance should keep running if it has:
                # 1. Name + Other tags, OR
                # 2. Only other tags (no name)
                is_compliant = (has_name and has_other_tags) or (not has_name and has_other_tags)
                
                if is_compliant:
                    valid_instances.append({
                        'instance_id': instance_id,
                        'name': instance_name if has_name else 'No Name',
                        'tags': tag_details,
                        'state': instance_state
                    })
                    
                    if has_name and has_other_tags:
                        logger.info(f"✓ Instance {instance_id} ({instance_name}) is COMPLIANT - has name and other tags: [{', '.join(tag_details)}] (State: {instance_state})")
                    else:
                        logger.info(f"✓ Instance {instance_id} is COMPLIANT - has tags (no name): [{', '.join(tag_details)}] (State: {instance_state})")
                else:
                    # Determine why it's non-compliant
                    if has_name and not has_other_tags:
                        reason = "has ONLY NAME tag, no other tags"
                    else:
                        reason = "has NO NAME and NO TAGS"
                    
                    instances_to_stop.append({
                        'instance_id': instance_id,
                        'state': instance_state,
                        'reason': reason
                    })
                    logger.warning(f"✗ Instance {instance_id} is NON-COMPLIANT - {reason} - will be stopped (State: {instance_state})")
        
        # Stop instances without tags
        stop_results = {}
        stopped_count = 0
        
        if instances_to_stop:
            # Extract instance IDs to stop
            instance_ids_to_stop = [inst['instance_id'] for inst in instances_to_stop]
            
            logger.info(f"Stopping {len(instance_ids_to_stop)} instances without tags: {instance_ids_to_stop}")
            
            # Stop the instances
            stop_response = ec2_client.stop_instances(InstanceIds=instance_ids_to_stop)
            
            # Process the response
            for state_change in stop_response.get('StoppingInstances', []):
                instance_id = state_change['InstanceId']
                prev_state = state_change['PreviousState']['Name']
                current_state = state_change['CurrentState']['Name']
                stop_results[instance_id] = {
                    'previous_state': prev_state,
                    'current_state': current_state,
                    'message': f"State changed from {prev_state} to {current_state}"
                }
                stopped_count += 1
                logger.info(f"✓ Instance {instance_id}: State changed from {prev_state} to {current_state}")
        else:
            logger.info("No instances found without tags - all running instances are properly tagged")
        
        # Prepare comprehensive result
        result_summary = {
            'total_running_instances': len(valid_instances) + len(instances_to_stop),
            'instances_with_tags': len(valid_instances),
            'instances_without_tags': len(instances_to_stop),
            'instances_stopped': stopped_count
        }
        
        # Define result_message here (after stopped_count and valid_instances are set)
        result_message = f"Tag compliance check completed. Stopped {stopped_count} non-compliant instances. {len(valid_instances)} compliant instances remain running."
        
        logger.info(f"SUMMARY: {result_message}")
        
        return {
            'statusCode': 200,
            'body': {
                'message': result_message,
                'summary': result_summary,
                'valid_instances': valid_instances,
                'instances_stopped': instances_to_stop,
                'stop_results': stop_results
            }
        }
    
    except Exception as e:
        error_message = f"Lambda execution failed: {str(e)}"
        logger.error(error_message)
        logger.error(f"Error type: {type(e).__name__}")
        
        return {
            'statusCode': 500,
            'body': {
                'error': error_message,
                'error_type': type(e).__name__
            }
        }