// Package postgres implements persistency with postgresql
//go:generate go-bindata -pkg postgres -ignore .*\.go .
//go:generate go fmt ./...
package postgres

import (
	"context"
	"encoding/hex"
	"goygg/internal/ygg/model"
	"log"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	bindata "github.com/golang-migrate/migrate/v4/source/go_bindata"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// Repository implementation with postgresql persistency
type Repository struct {
	DB                    *sqlx.DB
	stmtRemoveTokens      *sqlx.NamedStmt
	stmtCreateToken       *sqlx.NamedStmt
	stmtUpdateToken       *sqlx.NamedStmt
	stmtLoadTokenByUserID *sqlx.NamedStmt
	stmtLoadTokenByAccess *sqlx.NamedStmt
	stmtLoadTokenByClient *sqlx.NamedStmt
	stmtCreateUser        *sqlx.NamedStmt
	stmtUpdateUser        *sqlx.NamedStmt
	stmtLoadUserByID      *sqlx.NamedStmt
	stmtLoadUserByEmail   *sqlx.NamedStmt
	stmtLoadUserByName    *sqlx.NamedStmt
}

// New postgresql implementation
func New(db *sqlx.DB) (repo *Repository, err error) {
	repo = &Repository{
		DB: db,
	}

	err = repo.Migrate()
	if err != nil {
		return nil, err
	}

	repo.stmtRemoveTokens, err = db.PrepareNamed(queryRemoveTokens)
	if err != nil {
		return nil, err
	}

	repo.stmtCreateToken, err = db.PrepareNamed(queryCreateToken)
	if err != nil {
		return nil, err
	}

	repo.stmtUpdateToken, err = db.PrepareNamed(queryUpdateToken)
	if err != nil {
		return nil, err
	}

	repo.stmtLoadTokenByUserID, err = db.PrepareNamed(queryLoadTokenByUserID)
	if err != nil {
		return nil, err
	}

	repo.stmtLoadTokenByAccess, err = db.PrepareNamed(queryLoadTokenByAccess)
	if err != nil {
		return nil, err
	}

	repo.stmtLoadTokenByClient, err = db.PrepareNamed(queryLoadTokenByClient)
	if err != nil {
		return nil, err
	}

	repo.stmtCreateUser, err = db.PrepareNamed(queryCreateUser)
	if err != nil {
		return nil, err
	}

	repo.stmtUpdateUser, err = db.PrepareNamed(queryUpdateUser)
	if err != nil {
		return nil, err
	}

	repo.stmtLoadUserByID, err = db.PrepareNamed(queryLoadUserByID)
	if err != nil {
		return nil, err
	}

	repo.stmtLoadUserByEmail, err = db.PrepareNamed(queryLoadUserByEmail)
	if err != nil {
		return nil, err
	}

	repo.stmtLoadUserByName, err = db.PrepareNamed(queryLoadUserByName)
	if err != nil {
		return nil, err
	}

	return repo, nil
}

// Migrate implementation
func (repo *Repository) Migrate() error {
	source, err := bindata.WithInstance(bindata.Resource(AssetNames(), Asset))
	if err != nil {
		panic(err)
	}

	driver, err := postgres.WithInstance(repo.DB.DB, &postgres.Config{})
	if err != nil {
		panic(err)
	}

	m, err := migrate.NewWithInstance("go-bindata", source, "postgres", driver)
	if err != nil {
		panic(err)
	}

	err = m.Up()

	if err == nil {
		log.Println("Migrated.")
	} else if err == migrate.ErrNoChange {
		log.Println("Migration not required.")
		err = nil
	}

	return err
}

const queryRemoveTokens = `
delete from tokens where user_id = :user_id;
`

// RemoveTokens implementation
func (repo *Repository) RemoveTokens(ctx context.Context, userID string) error {
	_, err := repo.stmtRemoveTokens.ExecContext(ctx, &model.Token{UserID: userID})
	return err
}

const queryCreateToken = `
insert into tokens (
  user_id, 
  access, 
  client
) values (
  :user_id,
  :access,
  :client
) returning *;
`

func newUUID() string {
	u := uuid.New()
	return hex.EncodeToString(u[:])
}

// CreateToken implementation
func (repo *Repository) CreateToken(ctx context.Context, userID, client string) (tok *model.Token, err error) {
	tok = &model.Token{
		UserID: userID,
		Access: newUUID(),
		Client: client,
	}

	err = repo.stmtCreateToken.GetContext(ctx, tok, tok)
	if err != nil {
		return nil, err
	}

	return
}

const queryUpdateToken = `
update tokens set
  access = :access,
  issued_at = now()
where
  user_id = :user_id
returning *;
`

// UpdateToken implementation
func (repo *Repository) UpdateToken(ctx context.Context, userID string) (tok *model.Token, err error) {
	tok = &model.Token{
		UserID: userID,
		Access: newUUID(),
	}

	err = repo.stmtUpdateToken.GetContext(ctx, tok, tok)
	if err != nil {
		return nil, err
	}

	return
}

const queryLoadTokenByUserID = `
select * from tokens where user_id = :user_id;
`

// LoadTokenByUserID implementation
func (repo *Repository) LoadTokenByUserID(ctx context.Context, userID string) (tok *model.Token, err error) {
	tok = &model.Token{
		UserID: userID,
	}

	err = repo.stmtLoadTokenByUserID.GetContext(ctx, tok, tok)
	if err != nil {
		return nil, err
	}

	return
}

const queryLoadTokenByAccess = `
select * from tokens where access = :access;
`

// LoadTokenByAccess implementation
func (repo *Repository) LoadTokenByAccess(ctx context.Context, access string) (tok *model.Token, err error) {
	tok = &model.Token{
		Access: access,
	}

	err = repo.stmtLoadTokenByAccess.GetContext(ctx, tok, tok)
	if err != nil {
		return nil, err
	}

	return
}

const queryLoadTokenByClient = `
select * from tokens where client = :client;
`

// LoadTokenByClient implementation
func (repo *Repository) LoadTokenByClient(ctx context.Context, client string) (tok *model.Token, err error) {
	tok = &model.Token{
		Client: client,
	}

	err = repo.stmtLoadTokenByClient.GetContext(ctx, tok, tok)
	if err != nil {
		return nil, err
	}

	return
}

const queryCreateUser = `
insert into users(
  id, 
  password,
  email,
  profile_id,
  profile_name
) values (
  :id,
  :password,
  :email,
  :profile_id,
  :profile_name
) returning *;`

// CreateUser implementation
func (repo *Repository) CreateUser(ctx context.Context, name, email, password string) (usr *model.User, err error) {
	id := newUUID()
	usr = &model.User{
		ID:          id,
		Email:       email,
		Password:    password,
		ProfileID:   id,
		ProfileName: name,
	}

	err = repo.stmtCreateUser.GetContext(ctx, usr, usr)
	if err != nil {
		return nil, err
	}

	return usr, nil
}

const queryUpdateUser = `
update users set 
  profile_texture_skin_url = :profile_texture_skin_url,
  profile_texture_skin_model = :profile_texture_skin_model,
  profile_texture_cape_url = :profile_texture_cape_url,
  profile_name = :profile_name
where
  id = :id
returning *; 
`

// UpdateUser implementation
func (repo *Repository) UpdateUser(ctx context.Context, usr *model.User) (err error) {
	return repo.stmtCreateUser.GetContext(ctx, usr, usr)
}

const queryLoadUserByID = `
select * from users where id = :id;
`

// LoadUserByID implementation
func (repo *Repository) LoadUserByID(ctx context.Context, id string) (usr *model.User, err error) {
	usr = &model.User{ID: id}

	err = repo.stmtCreateUser.GetContext(ctx, usr, usr)
	if err != nil {
		return nil, err
	}

	return usr, nil
}

const queryLoadUserByEmail = `
select * from users where email = :email;
`

// LoadUserByEmail implementation
func (repo *Repository) LoadUserByEmail(ctx context.Context, email string) (usr *model.User, err error) {
	usr = &model.User{Email: email}

	err = repo.stmtCreateUser.GetContext(ctx, usr, usr)
	if err != nil {
		return nil, err
	}

	return usr, nil
}

const queryLoadUserByName = `
select * from users where profile_name = :profile_name;
`

// LoadUserByName implementation
func (repo *Repository) LoadUserByName(ctx context.Context, name string) (usr *model.User, err error) {
	usr = &model.User{ProfileName: name}

	err = repo.stmtCreateUser.GetContext(ctx, usr, usr)
	if err != nil {
		return nil, err
	}

	return usr, nil
}
