import boto3
import json
import os
import time

# Initialize clients outside the handler to optimize performance
ec2_client = boto3.client('ec2', region_name='us-east-1')
sns_client = boto3.client('sns', region_name='us-east-1')
logs_client = boto3.client('logs', region_name='us-east-1')

SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
NACL_ID = os.environ['NACL_ID']

def get_source_ip_from_logs(alarm_name):
    """Query CloudWatch Logs to find source IP related to the security alarm"""
    log_group = '/aws/cloudtrail/logs'
    
    # Standardized queries to safely isolate the client's public IP address
    query_map = {
        'IAMMisuse-Alarm': 'fields sourceIPAddress | filter userIdentity.userName="dev-test" | sort @timestamp desc | limit 1',
        'PrivEsc-Alarm': 'fields sourceIPAddress | filter eventName in ["AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy"] | sort @timestamp desc | limit 1',
        'APIBurst-Alarm': 'fields sourceIPAddress | filter userIdentity.userName="dev-test" | sort @timestamp desc | limit 1',
        'PortScan-Alarm': None,       # VPC Flow logs handle alerts via generic traffic volume
        'LateralMovement-Alarm': None  # Traffic is internal; no external public IP to block
    }
    
    query = query_map.get(alarm_name)
    if not query:
        return None
    
    try:
        # Scan the last 15 minutes of historical log delivery frames
        start = int(time.time()) - 900
        end = int(time.time())
        
        # Launch CloudWatch Insights background search job
        response = logs_client.start_query(
            logGroupName=log_group,
            startTime=start,
            endTime=end,
            queryString=query
        )
        query_id = response['queryId']
        
        # Polling loops to allow CloudWatch engine data compilation to finish
        for _ in range(6):
            time.sleep(2)
            results = logs_client.get_query_results(queryId=query_id)
            if results['status'] in ['Complete', 'Failed', 'Cancelled']:
                break
                
        # Robustly extract value out of nested log result rows
        for row in results.get('results', []):
            for field in row:
                if field['field'] == 'sourceIPAddress' and field['value'] != 'N/A':
                    return field['value']
    except Exception as e:
        print(f"CloudWatch Log Query Execution Failed: {str(e)}")
        
    return None

def lambda_handler(event, context):
    # Safely parse incoming CloudWatch Alarm EventBridge properties
    detail = event.get('detail', {})
    alarm_name = detail.get('alarmName', 'Unknown')
    alarm_state = detail.get('state', {}).get('value', '')
    reason = detail.get('state', {}).get('reason', '')
    
    # Drop evaluation early if event notification is just transitioning back to OK state
    if alarm_state != 'ALARM':
        print(f'Alarm {alarm_name} status moved to {alarm_state} - mitigation skipped.')
        return {'statusCode': 200, 'body': 'Irrelevant state change'}
        
    # Attempt to dynamically harvest malicious attacker location footprints
    src_ip = get_source_ip_from_logs(alarm_name)
    
    # Construct actionable monitoring email layout
    msg = "=========================================\n"
    msg += "🚨 AUTOMATED SECURITY DEFENSE ALERT\n"
    msg += "=========================================\n"
    msg += f"Detection Rule : {alarm_name}\n"
    msg += f"Current State  : {alarm_state}\n"
    msg += f"Incident Root  : {reason}\n"
    msg += f"Attacker IP    : {src_ip or 'N/A (Log collection queue indexing latency)'}\n"
    msg += "-----------------------------------------\n"
    
    # Block IP via NACL rule 90 for direct credential threat identities
    if src_ip and alarm_name in ['IAMMisuse-Alarm', 'PrivEsc-Alarm', 'APIBurst-Alarm']:
        try:
            ec2_client.create_network_acl_entry(
                NetworkAclId=NACL_ID,
                RuleNumber=90,
                Protocol='-1',  # Matches all protocols
                RuleAction='deny',
                Egress=False,   # Block traffic coming in
                CidrBlock=f'{src_ip}/32'
            )
            msg += f"Remediation Action: Network Access Rule #90 injected. {src_ip} dropped.\n"
        except Exception as e:
            msg += f"Remediation Action Failure: Could not build block entry -> {str(e)}\n"
    else:
        msg += "Remediation Action: Perimeter stable. Alert routed to SOC panel for manual inspection.\n"
        
    # Dispatch real-time telemetry notifications to down-stream analysts
    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"AWS SECURITY CRITICAL - {alarm_name}",
        Message=msg
    )
    
    print(msg)
    return {'statusCode': 200, 'body': 'Incident remediation cycle finished smoothly'}