package dashboardapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/BuildAndDestroy/owasp-scanner/pkg/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const collectionName = "scan_reports"

// ErrNotFound is returned when a report id does not exist.
var ErrNotFound = errors.New("report not found")

// StoredReport is persisted in MongoDB.
type StoredReport struct {
	ID         primitive.ObjectID `bson:"_id,omitempty"`
	CreatedAt  time.Time          `bson:"created_at"`
	TargetURL  string             `bson:"target_url"`
	ReportJSON string             `bson:"report_json"`
}

// Store handles MongoDB persistence.
type Store struct {
	client *mongo.Client
	coll   *mongo.Collection
}

// NewStore connects and returns a Store for the given database name.
func NewStore(ctx context.Context, uri, database string) (*Store, error) {
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("mongo connect: %w", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(ctx)
		return nil, fmt.Errorf("mongo ping: %w", err)
	}
	coll := client.Database(database).Collection(collectionName)
	_, _ = coll.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "created_at", Value: -1}}},
		{Keys: bson.D{{Key: "target_url", Value: 1}}},
	})
	return &Store{client: client, coll: coll}, nil
}

// Close disconnects the MongoDB client.
func (s *Store) Close(ctx context.Context) error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Disconnect(ctx)
}

// InsertReport validates and stores a scan report JSON document.
func (s *Store) InsertReport(ctx context.Context, report *models.ScanReport) (primitive.ObjectID, error) {
	if report == nil || report.TargetURL == "" {
		return primitive.NilObjectID, errors.New("invalid report")
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return primitive.NilObjectID, err
	}
	doc := StoredReport{
		CreatedAt:  time.Now().UTC(),
		TargetURL:  report.TargetURL,
		ReportJSON: string(raw),
	}
	res, err := s.coll.InsertOne(ctx, doc)
	if err != nil {
		return primitive.NilObjectID, err
	}
	return res.InsertedID.(primitive.ObjectID), nil
}

// ListMeta is a minimal row for the report list UI.
type ListMeta struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	TargetURL string `json:"target_url"`
}

// ListReports returns recent reports, newest first.
func (s *Store) ListReports(ctx context.Context, limit int64) ([]ListMeta, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}).SetLimit(limit)
	opts.SetProjection(bson.M{"target_url": 1, "created_at": 1})
	cur, err := s.coll.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var out []ListMeta
	for cur.Next(ctx) {
		var doc StoredReport
		if err := cur.Decode(&doc); err != nil {
			return nil, err
		}
		out = append(out, ListMeta{
			ID:        doc.ID.Hex(),
			CreatedAt: doc.CreatedAt.Format(time.RFC3339),
			TargetURL: doc.TargetURL,
		})
	}
	return out, cur.Err()
}

// GetReport loads and unmarshals a full scan report by id.
func (s *Store) GetReport(ctx context.Context, id string) (*models.ScanReport, error) {
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, ErrNotFound
	}
	var doc StoredReport
	if err := s.coll.FindOne(ctx, bson.M{"_id": oid}).Decode(&doc); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var rep models.ScanReport
	if err := json.Unmarshal([]byte(doc.ReportJSON), &rep); err != nil {
		return nil, err
	}
	return &rep, nil
}
