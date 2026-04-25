//go:build cgo

package fido2

import (
	"log"
	"runtime"
	"sync"
)

// Worker serializes all libfido2 calls through a single goroutine.
// Concurrent callers enqueue work items; worker executes them one at a time.
type Worker struct {
	ch   chan workItem
	once sync.Once
}

type workItem struct {
	fn     func()
	done   chan struct{}
}

var globalWorker = &Worker{ch: make(chan workItem, 64)}

func init() {
	go globalWorker.run()
}

func (w *Worker) run() {
	runtime.LockOSThread()
	for item := range w.ch {
		item.fn()
		close(item.done)
	}
}

// Run enqueues fn and blocks until it completes.
func (w *Worker) Run(fn func()) {
	item := workItem{fn: fn, done: make(chan struct{})}
	w.ch <- item
	<-item.done
}

// RunAsync enqueues fn; caller must wait on returned channel.
func (w *Worker) RunAsync(fn func()) <-chan struct{} {
	item := workItem{fn: fn, done: make(chan struct{})}
	select {
	case w.ch <- item:
		return item.done
	default:
		log.Println("fido2 worker: queue full, dropping item")
		close(item.done)
		return item.done
	}
}
