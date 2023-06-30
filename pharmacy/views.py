import json
from django.http import HttpResponse, JsonResponse

import jwt
from datetime import datetime, timedelta

import secrets

import boto3
from boto3.dynamodb.conditions import Key

from django.http import (
    HttpResponseBadRequest,
    HttpResponseNotAllowed,
    HttpResponseForbidden,
)
from django.http import HttpResponseNotFound, HttpResponseServerError
from django.http import Http404
from django.http import (
    HttpResponseBadRequest,
    HttpResponseForbidden,
    HttpResponseNotFound,
    HttpResponseServerError,
)
from django.views.decorators.csrf import csrf_exempt

import json


secret_key = secrets.token_hex(32)


@csrf_exempt
def login(request):
    data = json.loads(request.body)
    username = data["username"]
    password = data["password"]

    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")

    table_name = "LoginCredentials"

    table = dynamodb.Table(table_name)

    query_params = {
        "KeyConditionExpression": Key("username").eq(username),
        "FilterExpression": Key("password").eq(password),
    }

    response = table.query(**query_params)
    if response.get("Items"):
        payload = {"username": "myuser", "exp": datetime.utcnow() + timedelta(days=1)}
        token = jwt.encode(payload, secret_key)
        return JsonResponse({"token": token}, status=200)
    else:
        return JsonResponse({"error": "Invalid username or password"}, status=200)


@csrf_exempt
def prescription(request, prescription_id):
    if verify_token(request) == False:
        return JsonResponse({"error": "Invalid username or password"}, status=200)

    client = boto3.client("stepfunctions", region_name="us-east-1")

    input_data = {"id": prescription_id}

    state_machine_arn = (
        "arn:aws:states:us-east-1:068263486969:stateMachine:obtainPrescription"
    )

    response = client.start_execution(
        stateMachineArn=state_machine_arn, input=json.dumps(input_data)
    )

    execution_arn = response["executionArn"]

    execution_output = client.describe_execution(executionArn=execution_arn)

    while execution_output["status"] == "RUNNING":
        execution_output = client.describe_execution(executionArn=execution_arn)

    return JsonResponse({"message": execution_output["output"]}, status=200)


@csrf_exempt
def payment(request, prescription_id):
    if verify_token(request) == False:
        return HttpResponse("Not auth")

    data = json.loads(request.body)
    client = boto3.client("stepfunctions", region_name="us-east-1")

    state_machine_arn = (
        "arn:aws:states:us-east-1:068263486969:stateMachine:FinalizeOrder"
    )

    response = client.start_execution(
        stateMachineArn=state_machine_arn, input=json.dumps(data)
    )

    execution_arn = response["executionArn"]

    execution_output = client.describe_execution(executionArn=execution_arn)

    while execution_output["status"] == "RUNNING":
        execution_output = client.describe_execution(executionArn=execution_arn)

    data = json.loads(execution_output["output"])["result"]["statusCode"]
    if data != 200:
        return JsonResponse({"message": "wrond payment auth"}, status=202)
    else:
        return JsonResponse({"message": "Sucess"}, status=200)


@csrf_exempt
def orders(request):
    if verify_token(request) == False:
        return JsonResponse({"error": "Invalid username or password"})

    client = boto3.client("stepfunctions", region_name="us-east-1")

    input_data = {}

    state_machine_arn = "arn:aws:states:us-east-1:068263486969:stateMachine:getOrders"

    response = client.start_execution(
        stateMachineArn=state_machine_arn, input=json.dumps(input_data)
    )

    execution_arn = response["executionArn"]

    execution_output = client.describe_execution(executionArn=execution_arn)

    while execution_output["status"] == "RUNNING":
        execution_output = client.describe_execution(executionArn=execution_arn)

    data = json.loads(execution_output["output"])["response"]
    return JsonResponse({"message": data}, status=200)


@csrf_exempt
def orderConfirm(request, orderId):
    if verify_token(request) == False:
        return JsonResponse({"error": "Invalid username or password"})

    client = boto3.client("stepfunctions", region_name="us-east-1")

    input_data = {"orderId": orderId}

    state_machine_arn = (
        "arn:aws:states:us-east-1:068263486969:stateMachine:confirmOrder"
    )

    response = client.start_execution(
        stateMachineArn=state_machine_arn, input=json.dumps(input_data)
    )

    execution_arn = response["executionArn"]

    execution_output = client.describe_execution(executionArn=execution_arn)

    while execution_output["status"] == "RUNNING":
        execution_output = client.describe_execution(executionArn=execution_arn)

    data = json.loads(execution_output["output"])
    return JsonResponse({"message": execution_output["output"]}, status=200)


@csrf_exempt
def verify_token(request):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return False
    token = auth_header[len("Bearer ") :]
    try:
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        return True
    except jwt.exceptions.InvalidSignatureError:
        print("Invalid")

        return False
    except jwt.exceptions.ExpiredSignatureError:
        print("Expired")
        return False
