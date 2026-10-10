package main

import (
	"context"
	"errors"

	"mossward/internal/workerapp"
)

func runWorker(ctx context.Context, config workerapp.Config) (result error) {
	app, err := workerapp.New(config)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, app.Close()) }()
	return app.Run(ctx)
}
