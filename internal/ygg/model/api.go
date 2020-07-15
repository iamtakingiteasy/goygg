// Package model persistency
package model

import (
	"context"
	"time"
)

// Repository persistency interface
type Repository interface {
	Migrate() error
	RemoveTokens(ctx context.Context, userID string) error
	CreateToken(ctx context.Context, userID, client string) (*Token, error)
	UpdateToken(ctx context.Context, userID string) (*Token, error)
	LoadTokenByUserID(ctx context.Context, userID string) (*Token, error)
	LoadTokenByAccess(ctx context.Context, access string) (*Token, error)
	LoadTokenByClient(ctx context.Context, client string) (*Token, error)
	CreateUser(ctx context.Context, name, email, password string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	LoadUserByID(ctx context.Context, id string) (*User, error)
	LoadUserByEmail(ctx context.Context, email string) (*User, error)
	LoadUserByName(ctx context.Context, name string) (*User, error)
}

// Token model
type Token struct {
	UserID   string    `db:"user_id"`
	Access   string    `db:"access"`
	Client   string    `db:"client"`
	IssuedAt time.Time `db:"issued_at"`
}

// User model
type User struct {
	ID                      string `db:"id"`
	Email                   string `db:"email"`
	Password                string `db:"password"`
	ProfileID               string `db:"profile_id"`
	ProfileName             string `db:"profile_name"`
	ProfileTextureSkinURL   string `db:"profile_texture_skin_url"`
	ProfileTextureSkinModel string `db:"profile_texture_skin_model"`
	ProfileTextureCapeURL   string `db:"profile_texture_cape_url"`
}
