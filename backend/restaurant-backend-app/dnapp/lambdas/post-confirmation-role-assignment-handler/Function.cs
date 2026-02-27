using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using Amazon.Lambda.Core;
using Amazon.Lambda.CognitoEvents;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace PostConfirmationRoleAssignmentHandler;

public class Function
{
    private readonly IAmazonDynamoDB _dynamoDbClient;
    private readonly IAmazonCognitoIdentityProvider _cognitoClient;

    private readonly string _waitersTableName;
    private readonly string _waiterGroupName;
    private readonly string _customerGroupName;

    public Function()
    {
        _dynamoDbClient = new AmazonDynamoDBClient();
        _cognitoClient = new AmazonCognitoIdentityProviderClient();

        _waitersTableName = Environment.GetEnvironmentVariable("WAITER_TABLE_NAME") ?? "waiters-list-table";
        _waiterGroupName = Environment.GetEnvironmentVariable("WAITER_GROUP_NAME") ?? "WAITER";
        _customerGroupName = Environment.GetEnvironmentVariable("CUSTOMER_GROUP_NAME") ?? "CUSTOMER";
    }

    public async Task<CognitoPostConfirmationEvent> HandleAsync(CognitoPostConfirmationEvent postConfirmationEvent, ILambdaContext context)
    {
        var email = postConfirmationEvent.Request.UserAttributes.TryGetValue("email", out var value)
            ? value?.Trim()
            : null;

        if (string.IsNullOrWhiteSpace(email))
        {
            context.Logger.LogWarning("Post-confirmation event does not contain user email. Skipping role assignment.");
            return postConfirmationEvent;
        }

        var isWaiter = await IsWaiterEmailAsync(email);
        var targetGroup = isWaiter ? _waiterGroupName : _customerGroupName;

        await EnsureGroupExistsAsync(postConfirmationEvent.UserPoolId, targetGroup);
        await AssignUserToGroupAsync(postConfirmationEvent.UserPoolId, postConfirmationEvent.UserName, targetGroup);

        context.Logger.LogInformation($"Assigned user '{postConfirmationEvent.UserName}' to '{targetGroup}' group.");

        return postConfirmationEvent;
    }

    private async Task<bool> IsWaiterEmailAsync(string email)
    {
        var normalizedEmail = email.ToLowerInvariant();
        if (await WaiterRecordExistsAsync(normalizedEmail))
        {
            return true;
        }

        return normalizedEmail != email && await WaiterRecordExistsAsync(email);
    }

    private async Task<bool> WaiterRecordExistsAsync(string email)
    {
        var response = await _dynamoDbClient.GetItemAsync(new GetItemRequest
        {
            TableName = _waitersTableName,
            Key = new Dictionary<string, AttributeValue>
            {
                ["email"] = new AttributeValue { S = email }
            },
            ProjectionExpression = "email"
        });

        return response.Item.Count > 0;
    }

    private async Task EnsureGroupExistsAsync(string userPoolId, string groupName)
    {
        try
        {
            await _cognitoClient.CreateGroupAsync(new CreateGroupRequest
            {
                GroupName = groupName,
                UserPoolId = userPoolId
            });
        }
        catch (GroupExistsException)
        {
            // Group already exists, proceed.
        }
    }

    private async Task AssignUserToGroupAsync(string userPoolId, string username, string groupName)
    {
        await _cognitoClient.AdminAddUserToGroupAsync(new AdminAddUserToGroupRequest
        {
            UserPoolId = userPoolId,
            Username = username,
            GroupName = groupName
        });
    }
}
