"""Offline source-to-policy coverage, not an effective-permissions IAM simulator."""

import ast
import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from functools import lru_cache
from itertools import product
from pathlib import Path

import botocore.session
from botocore import xform_name
import yaml


class CfnLoader(yaml.SafeLoader):
    pass


def _intrinsic(loader, tag, node):
    key = tag if tag in {"Ref", "Condition"} else f"Fn::{tag}"
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {key: value}


CfnLoader.add_multi_constructor("!", _intrinsic)


def load_template(path):
    # SafeLoader's intrinsic handler constructs plain data, never Python objects.
    return yaml.load(Path(path).read_text(encoding="utf-8"), Loader=CfnLoader)  # nosec B506


def _list(value):
    return value if isinstance(value, list) else [value]


def function_statements(template, logical_id):
    """Read only policies actually attached to this function or its local role."""
    resources = template["Resources"]
    statements = []
    visited = set()

    def collect(value):
        if isinstance(value, list):
            for item in value:
                collect(item)
        elif isinstance(value, dict):
            if "Fn::If" in value:
                # Assert declared coverage in either configuration, not condition truth.
                collect(value["Fn::If"][1:])
            elif "Statement" in value:
                collect(value["Statement"])
            elif "PolicyDocument" in value:
                collect(value["PolicyDocument"])
            elif "Action" in value:
                if value.get("Effect") == "Allow":
                    statements.append(value)
            elif "Ref" in value and value["Ref"] in resources:
                reference(value["Ref"])
            elif "Fn::GetAtt" in value:
                target = value["Fn::GetAtt"]
                reference(
                    target.split(".")[0] if isinstance(target, str) else target[0]
                )
            elif "Fn::Sub" in value and isinstance(value["Fn::Sub"], str):
                for name in resources:
                    if "${" + name + "}" in value["Fn::Sub"]:
                        reference(name)

    def reference(name):
        if name in visited:
            return
        visited.add(name)
        resource = resources.get(name, {})
        props = resource.get("Properties", {})
        if resource.get("Type") == "AWS::IAM::ManagedPolicy":
            collect(props.get("PolicyDocument", {}))
        elif resource.get("Type") == "AWS::IAM::Role":
            collect(props.get("Policies", []))
            collect(props.get("ManagedPolicyArns", []))

    props = resources[logical_id]["Properties"]
    collect(props.get("Policies", []))
    collect(props.get("Role", {}))
    return statements


def granted_actions(template, logical_id):
    return {
        action.lower()
        for statement in function_statements(template, logical_id)
        for action in _list(statement["Action"])
        if isinstance(action, str)
    }


# SDK endpoint names are not IAM namespaces for these services.
IAM_PREFIX = {
    "bedrock-agent": "bedrock",
    "bedrock-runtime": "bedrock",
    "bedrock-agentcore-control": "bedrock-agentcore",
    "agent-registry-control": "agent-registry",
    "stepfunctions": "states",
    "cloudwatch": "cloudwatch",
    "efs": "elasticfilesystem",
    "resourcegroupstaggingapi": "tag",
    "sso-admin": "sso",
    "opensearchserverless": "aoss",
    "application-autoscaling": "application-autoscaling",
    "lambda-core": "lambda",
    "lambda-microvms": "lambda",
    "service-quotas": "servicequotas",
    "appconfigdata": "appconfig",
    "accessanalyzer": "access-analyzer",
    "opensearch": "es",
}

# API operation names are not always the action checked by IAM.
ACTION_ALIASES = {
    ("s3", "GetBucketEncryption"): "s3:GetEncryptionConfiguration",  # IAM omits Bucket.
    (
        "s3",
        "ListObjects",
    ): "s3:ListBucket",  # Object inventory uses bucket authorization.
    ("s3", "ListObjectsV2"): "s3:ListBucket",  # V2 shares the same bucket action.
    ("s3", "HeadObject"): "s3:GetObject",  # Metadata reads use the object read action.
    ("s3", "HeadBucket"): "s3:ListBucket",  # Bucket existence uses list authorization.
    (
        "s3",
        "GetBucketNotificationConfiguration",
    ): "s3:GetBucketNotification",  # IAM omits Configuration.
    (
        "s3",
        "DeleteObjects",
    ): "s3:DeleteObject",  # A batch authorizes each object delete.
    ("s3", "ListBuckets"): "s3:ListAllMyBuckets",  # Account-wide bucket inventory.
    (
        "s3",
        "GetObjectLockConfiguration",
    ): "s3:GetBucketObjectLockConfiguration",  # The setting is bucket-level.
    (
        "s3",
        "GetBucketLifecycleConfiguration",
    ): "s3:GetLifecycleConfiguration",  # IAM omits Bucket.
    (
        "s3",
        "GetBucketReplication",
    ): "s3:GetReplicationConfiguration",  # IAM names the configuration.
    (
        "s3",
        "ListObjectVersions",
    ): "s3:ListBucketVersions",  # Versions are a bucket inventory.
    (
        "s3control",
        "GetPublicAccessBlock",
    ): "s3:GetAccountPublicAccessBlock",  # Account control plane.
    (
        "s3",
        "GetPublicAccessBlock",
    ): "s3:GetBucketPublicAccessBlock",  # Bucket control plane.
    (
        "budgets",
        "DescribeBudgets",
    ): "budgets:ViewBudget",  # Budget descriptions use ViewBudget.
    (
        "budgets",
        "DescribeBudget",
    ): "budgets:ViewBudget",  # Single-budget variant has the same action.
}
SDK_HELPERS = {
    "upload_file": "PutObject",
    "upload_fileobj": "PutObject",
    "download_file": "GetObject",
    "download_fileobj": "GetObject",
}


@lru_cache(maxsize=None)
def service_operations(service):
    model = botocore.session.get_session().get_service_model(service)
    return {xform_name(name): name for name in model.operation_names}, model.metadata


@lru_cache(maxsize=None)
def iam_action(service, method):
    operations, _metadata = service_operations(service)
    if method in SDK_HELPERS and service == "s3":
        operation = SDK_HELPERS[method]
    else:
        if method not in operations:
            raise AssertionError(f"Unknown SDK operation {service}.{method}")
        operation = operations[method]
    if service == "sts" and operation == "GetCallerIdentity":
        return None  # STS explicitly requires no IAM permission for this API.
    if service in {"apigateway", "apigatewayv2"}:
        model = botocore.session.get_session().get_service_model(service)
        return f"apigateway:{model.operation_model(operation).http['method']}"
    return ACTION_ALIASES.get(
        (service, operation), f"{IAM_PREFIX.get(service, service)}:{operation}"
    )


@dataclass(frozen=True)
class ApiCall:
    path: str
    line: int
    service: str
    method: str

    @property
    def action(self):
        try:
            return iam_action(self.service, self.method)
        except AssertionError as error:
            raise AssertionError(f"{self.path}:{self.line}: {error}") from error


def extract_calls(source, path="fixture.py"):
    """Resolve lexical client bindings and the client's actual service string."""
    tree = ast.parse(source)
    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    imported_clients = {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "boto3"
        for alias in node.names
        if alias.name == "client"
    }
    scopes = {None: tree, **functions}
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    def scope_of(node):
        while node in parents:
            node = parents[node]
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return node.name
        return None

    bindings = {}
    returns = {}
    strings = {}
    available_services = set(botocore.session.get_session().get_available_services())

    def literals(expr, scope):
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return {expr.value}
        if isinstance(expr, (ast.Name, ast.Attribute)):
            name = ast.unparse(expr)
            return strings.get((scope, name), strings.get((None, name), set()))
        if isinstance(expr, ast.JoinedStr):
            parts = [
                literals(n.value if isinstance(n, ast.FormattedValue) else n, scope)
                for n in expr.values
            ]
            return {"".join(p) for p in product(*parts)}
        if isinstance(expr, ast.IfExp):
            return literals(expr.body, scope) | literals(expr.orelse, scope)
        if isinstance(expr, ast.Subscript):
            return literals(expr.value, scope)
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return set().union(*(literals(n, scope) for n in expr.elts))
        if isinstance(expr, ast.Dict):
            return set().union(*(literals(n, scope) for n in expr.values))
        return set()

    def services(expr, scope):
        if isinstance(expr, (ast.Name, ast.Attribute, ast.Subscript)):
            name = ast.unparse(expr)
            held = bindings.get((scope, name), bindings.get((None, name), set()))
            if (
                not held
                and isinstance(expr, ast.Attribute)
                and isinstance(expr.value, ast.Name)
                and expr.value.id == "self"
            ):
                held = set().union(
                    *(v for (_, key), v in bindings.items() if key == expr.attr)
                )
            return held
        if isinstance(expr, ast.Call):
            if (
                isinstance(expr.func, ast.Attribute) and expr.func.attr == "client"
            ) or (isinstance(expr.func, ast.Name) and expr.func.id in imported_clients):
                service = (
                    expr.args[0]
                    if expr.args
                    else next(
                        (kw.value for kw in expr.keywords if kw.arg == "service_name"),
                        None,
                    )
                )
                if (
                    isinstance(service, ast.Constant)
                    and service.value not in available_services
                ):
                    raise AssertionError(
                        f"{path}:{expr.lineno}: unknown SDK service {service.value!r}"
                    )
                return literals(service, scope) & available_services
            if isinstance(expr.func, ast.Name):
                return returns.get(expr.func.id, set())
        return set()

    # Clients may be created in a handler and stored in a module-global variable.
    globals_by_scope = {
        scope: {
            name
            for node in ast.walk(body)
            if isinstance(node, ast.Global)
            for name in node.names
        }
        for scope, body in scopes.items()
    }
    for _ in range(12):
        old = repr((bindings, returns, strings))
        for node in ast.walk(tree):
            scope = scope_of(node)
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                for target in targets:
                    name = ast.unparse(target)
                    key = (
                        None if name in globals_by_scope.get(scope, set()) else scope,
                        name,
                    )
                    bindings.setdefault(key, set()).update(services(node.value, scope))
                    strings.setdefault(key, set()).update(literals(node.value, scope))
            elif isinstance(node, ast.For):
                targets = (
                    node.target.elts
                    if isinstance(node.target, ast.Tuple)
                    else [node.target]
                )
                for index, target in enumerate(targets):
                    values = literals(node.iter, scope)
                    if isinstance(node.iter, (ast.Tuple, ast.List)) and isinstance(
                        node.target, ast.Tuple
                    ):
                        values = set().union(
                            *(
                                literals(row.elts[index], scope)
                                for row in node.iter.elts
                                if isinstance(row, (ast.Tuple, ast.List))
                                and len(row.elts) > index
                            )
                        )
                    strings.setdefault((scope, ast.unparse(target)), set()).update(
                        values
                    )
            elif isinstance(node, ast.Return) and node.value is not None:
                returns.setdefault(scope, set()).update(services(node.value, scope))
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, (ast.Name, ast.Attribute))
                and (
                    node.func.id if isinstance(node.func, ast.Name) else node.func.attr
                )
                in functions
            ):
                fn = functions[
                    node.func.id if isinstance(node.func, ast.Name) else node.func.attr
                ]
                params = [p for p in fn.args.args if p.arg != "self"]
                for param, value in zip(params, node.args):
                    bindings.setdefault((fn.name, param.arg), set()).update(
                        services(value, scope)
                    )
                    strings.setdefault((fn.name, param.arg), set()).update(
                        literals(value, scope)
                    )
        if repr((bindings, returns, strings)) == old:
            break
    else:
        raise AssertionError(f"{path}: client binding analysis did not converge")

    calls = set()

    def add_methods(held, methods, line, dynamic=False):
        for method in methods:
            if dynamic and not re.fullmatch(
                r"(?:get|list|describe|batch|head|put|delete|generate|create|apply|invoke|simulate|lookup|filter|start|stop|check|select|search|detect|validate|is)_[a-z0-9_]+",
                method,
            ):
                continue
            matching = {
                service for service in held if method in service_operations(service)[0]
            }
            if held and not matching and len(held) > 1:
                raise AssertionError(
                    f"{path}:{line}: cannot resolve {method} on {sorted(held)}"
                )
            for service in matching or (held if len(held) == 1 else set()):
                calls.add(ApiCall(str(path), line, service, method))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        scope = scope_of(node)
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
        ):
            client, op = node.args[:2]
            if not (
                scope in functions
                and isinstance(client, ast.Name)
                and client.id in {p.arg for p in functions[scope].args.args}
            ):
                held = services(client, scope)
                methods = literals(op, scope)
                if held and not methods:
                    raise AssertionError(
                        f"{path}:{node.lineno}: unresolved dynamic SDK operation"
                    )
                add_methods(
                    held, methods, node.lineno, dynamic=not isinstance(op, ast.Constant)
                )
        if isinstance(node.func, ast.Attribute):
            method = node.func.attr
            held = services(node.func.value, scope)
            if (
                scope in functions
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in {p.arg for p in functions[scope].args.args}
            ):
                continue  # Pair helper parameters at each call site, not across callers.
            if method in {"get_paginator", "get_waiter"}:
                methods = literals(node.args[0], scope) if node.args else set()
                if not held:
                    continue
                if not methods:
                    raise AssertionError(f"{path}:{node.lineno}: unresolved paginator")
                add_methods(
                    held,
                    methods,
                    node.lineno,
                    dynamic=not isinstance(node.args[0], ast.Constant),
                )
                continue
            if method not in {"close", "can_paginate", "generate_presigned_url"}:
                add_methods(held, {method}, node.lineno)
        # Resolve string-op helper calls at the call site, pairing its client and op.
        name = (
            node.func.id
            if isinstance(node.func, ast.Name)
            else node.func.attr
            if isinstance(node.func, ast.Attribute)
            else None
        )
        if name in functions:
            helper = functions[name]
            values = dict(
                zip((p.arg for p in helper.args.args if p.arg != "self"), node.args)
            )
            values.update({kw.arg: kw.value for kw in node.keywords})
            for inner in ast.walk(helper):
                if (
                    isinstance(inner, ast.Call)
                    and isinstance(inner.func, ast.Attribute)
                    and isinstance(inner.func.value, ast.Name)
                    and inner.func.value.id in values
                ):
                    held = services(values[inner.func.value.id], scope)
                    method = inner.func.attr
                    if method == "get_paginator":
                        op = inner.args[0]
                        op = values.get(op.id, op) if isinstance(op, ast.Name) else op
                        add_methods(
                            held,
                            literals(op, scope),
                            node.lineno,
                            dynamic=not isinstance(op, ast.Constant),
                        )
                    elif method not in {
                        "close",
                        "can_paginate",
                        "generate_presigned_url",
                    }:
                        add_methods(held, {method}, node.lineno)
                if not (
                    isinstance(inner, ast.Call)
                    and isinstance(inner.func, ast.Name)
                    and inner.func.id == "getattr"
                    and len(inner.args) >= 2
                ):
                    continue
                client, op = inner.args[:2]
                if isinstance(client, ast.Name):
                    client = values.get(client.id, client)
                if isinstance(op, ast.Name):
                    op = values.get(op.id, op)
                add_methods(
                    services(client, scope),
                    literals(op, scope),
                    node.lineno,
                    dynamic=not isinstance(op, ast.Constant),
                )
    return calls


def missing_calls(calls, grants):
    return [
        call
        for call in calls
        if call.action
        and not any(fnmatchcase(call.action.lower(), pattern) for pattern in grants)
    ]
