package sqlite

import (
	"database/sql"
	"fmt"
	"time"
)

type sqliteScanner interface {
	Scan(dest ...any) error
}

func scanSQLiteAnomaly(row sqliteScanner) (Anomaly, error) {
	var a Anomaly
	var createdStr, updatedStr string
	if err := row.Scan(&a.ID, &a.IP, &a.DestinationIP, &a.Type, &a.Description, &a.Severity, &a.Status, &createdStr, &updatedStr); err != nil {
		return Anomaly{}, err
	}
	if t, err := time.Parse(time.RFC3339, createdStr); err == nil {
		a.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, updatedStr); err == nil {
		a.UpdatedAt = t
	}
	return a, nil
}

func scanSQLiteAnomalyRows(rows *sql.Rows, contextLabel string) ([]Anomaly, error) {
	var list []Anomaly
	for rows.Next() {
		a, err := scanSQLiteAnomaly(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan %s anomaly row: %w", contextLabel, err)
		}
		list = append(list, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating %s anomaly rows: %w", contextLabel, err)
	}
	if list == nil {
		list = []Anomaly{}
	}
	return list, nil
}
