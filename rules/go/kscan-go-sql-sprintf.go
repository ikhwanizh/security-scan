//go:build ignore

package example

import (
	"context"
	"database/sql"
	"fmt"

	"gorm.io/gorm"
)

func bad(ctx context.Context, db *sql.DB, g *gorm.DB, id, sort string) {
	// ruleid: kscan-go-sql-sprintf
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id))
	// ruleid: kscan-go-sql-sprintf
	db.ExecContext(ctx, fmt.Sprintf("DELETE FROM sessions WHERE user_id = %s", id))
	// ruleid: kscan-go-sql-sprintf
	q := fmt.Sprintf("SELECT * FROM docs ORDER BY %s", sort)
	g.Raw(q).Scan(nil)
}

func good(ctx context.Context, db *sql.DB, id string) {
	// ok: kscan-go-sql-sprintf
	db.QueryContext(ctx, "SELECT * FROM users WHERE id = $1", id)
	msg := fmt.Sprintf("user %s logged in", id)
	// ok: kscan-go-sql-sprintf
	db.Exec("INSERT INTO audit(msg) VALUES ($1)", msg)
}
