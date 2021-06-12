package s3

import (
	"context"
	"io"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	s3api "github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

type Config struct {
	Region    string       `yaml:"region,omitempty"`
	Bucket    string       `yaml:"bucket,omitempty"`
	Endpoint  string       `yaml:"endpoint,omitempty"`
	AccessKey string       `yaml:"access_key,omitempty"`
	SecretKey SecretString `yaml:"secret_key,omitempty"`
}

type SecretString string

func (s SecretString) MarshalYAML() (interface{}, error) {
	return "<redacted>", nil
}

type S3 struct {
	cfg *Config

	sess *session.Session
}

func (_ *S3) Name() string {
	return "s3"
}

func (s3 *S3) Upload(ctx context.Context, name string, r io.Reader) error {
	uploader := s3manager.NewUploader(s3.sess)
	_, err := uploader.UploadWithContext(ctx, &s3manager.UploadInput{
		Bucket: aws.String(s3.cfg.Bucket),
		Key:    aws.String(name),
		Body:   r,
	})
	return err
}

func (s3 *S3) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	svc := s3api.New(s3.sess)
	obj, err := svc.GetObjectWithContext(ctx, &s3api.GetObjectInput{
		Bucket: aws.String(s3.cfg.Bucket),
		Key:    aws.String(name),
	})

	if err != nil {
		return nil, err
	}
	return obj.Body, nil
}

func (s3 *S3) Exists(ctx context.Context, name string) (bool, error) {
	svc := s3api.New(s3.sess)
	_, err := svc.HeadObjectWithContext(ctx, &s3api.HeadObjectInput{
		Bucket: aws.String(s3.cfg.Bucket),
		Key:    aws.String(name),
	})
	if s3.IsObjNotFoundErr(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func (s3 *S3) IsObjNotFoundErr(err error) bool {
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3api.ErrCodeNoSuchKey, "NotFound":
				return true
			default:
				return false
			}
		}
		return false
	}
	return false
}

func New(cfg *Config) *S3 {
	var endpoint *string
	if cfg.Endpoint != "" {
		endpoint = aws.String(cfg.Endpoint)
	}

	var creds *credentials.Credentials
	if cfg.AccessKey != "" || cfg.SecretKey != "" {
		creds = credentials.NewStaticCredentials(
			cfg.AccessKey,
			string(cfg.SecretKey),
			"",
		)
	}

	var sess = session.Must(session.NewSessionWithOptions(session.Options{
		// Provide SDK Config options, such as Region.
		Config: aws.Config{
			Region:           aws.String(cfg.Region),
			Endpoint:         endpoint,
			S3ForcePathStyle: aws.Bool(true),
			Credentials:      creds,
		},
	}))

	return &S3{
		cfg:  cfg,
		sess: sess,
	}
}
