package storage

import (
	"context"
	"fmt"
	"log"
	"math"
	"strings"
	"time"

	"intrualert/types"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type Storage struct {
	client       *dynamodb.Client
	attackTable  string
	userTable    string
	trafficTable string // Changed from statsTable
}

func NewStorage(cfg aws.Config) (*Storage, error) {
	// Use AWS SDK V2's built-in retry mechanism
	cfg.RetryMaxAttempts = 5
	cfg.RetryMode = aws.RetryModeStandard

	client := dynamodb.NewFromConfig(cfg)

	return &Storage{
		client:       client,
		attackTable:  "AttackLogs",
		trafficTable: "TrafficStats",
	}, nil
}

// Add retries and better error handling for DynamoDB operations
func (s *Storage) StoreAttack(attack types.AttackLog) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	item, err := attributevalue.MarshalMap(attack)
	if err != nil {
		return fmt.Errorf("failed to marshal attack log: %w", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(s.attackTable),
		Item:      item,
	}

	// Use exponential backoff retry
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		_, err = s.client.PutItem(ctx, input)
		if err == nil {
			log.Printf("[INFO] Successfully stored attack %s in DynamoDB", attack.AttackID)
			return nil
		}

		lastErr = err
		if strings.Contains(err.Error(), "RequestLimitExceeded") {
			// Wait with exponential backoff
			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			time.Sleep(backoff)
			continue
		}

		// Don't retry other errors
		return fmt.Errorf("failed to store attack in DynamoDB: %w", err)
	}

	return fmt.Errorf("failed to store attack after retries: %w", lastErr)
}

func (s *Storage) StoreUser(user types.User) error {
	item, err := attributevalue.MarshalMap(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %w", err)
	}

	_, err = s.client.PutItem(context.Background(), &dynamodb.PutItemInput{
		TableName:           aws.String(s.userTable),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(Username)"),
	})
	if err != nil {
		return fmt.Errorf("failed to store user in DynamoDB: %w", err)
	}

	log.Printf("Stored user %s in DynamoDB", user.Username)
	return nil
}

func (s *Storage) GetUser(username string) (*types.User, error) {
	resp, err := s.client.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(s.userTable),
		Key: map[string]dynamodbtypes.AttributeValue{
			"Username": &dynamodbtypes.AttributeValueMemberS{Value: username},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get user from DynamoDB: %w", err)
	}

	if len(resp.Item) == 0 {
		return nil, nil
	}

	var user types.User
	err = attributevalue.UnmarshalMap(resp.Item, &user)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	return &user, nil
}

func (s *Storage) StoreTrafficStats(stats types.TrafficStats) error {
	item, err := attributevalue.MarshalMap(stats)
	if err != nil {
		return fmt.Errorf("failed to marshal traffic stats: %w", err)
	}

	_, err = s.client.PutItem(context.Background(), &dynamodb.PutItemInput{
		TableName: aws.String(s.trafficTable),
		Item:      item,
	})
	if err != nil {
		return fmt.Errorf("failed to store traffic stats in DynamoDB: %w", err)
	}

	log.Printf("Stored traffic stats in DynamoDB")
	return nil
}

func (s *Storage) GetAttacks() ([]types.AttackLog, error) {
	resp, err := s.client.Scan(context.Background(), &dynamodb.ScanInput{
		TableName: aws.String(s.attackTable),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan attacks from DynamoDB: %w", err)
	}

	var attacks []types.AttackLog
	err = attributevalue.UnmarshalListOfMaps(resp.Items, &attacks)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal attacks: %w", err)
	}

	return attacks, nil
}

func (s *Storage) GetAttacksByTimeRange(start, end time.Time) ([]types.AttackLog, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(s.attackTable),
		KeyConditionExpression: aws.String("Timestamp BETWEEN :start AND :end"),
		ExpressionAttributeValues: map[string]dynamodbtypes.AttributeValue{
			":start": &dynamodbtypes.AttributeValueMemberS{Value: start.Format(time.RFC3339)},
			":end":   &dynamodbtypes.AttributeValueMemberS{Value: end.Format(time.RFC3339)},
		},
		ScanIndexForward: aws.Bool(false), // Latest first
	}

	result, err := s.client.Query(context.Background(), input)
	if err != nil {
		return nil, fmt.Errorf("failed to query attacks: %w", err)
	}

	var attacks []types.AttackLog
	err = attributevalue.UnmarshalListOfMaps(result.Items, &attacks)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal attacks: %w", err)
	}

	return attacks, nil
}
