package prototype

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

const (
	// Establishment is deliberately isolated from the encrypted dataplane. The
	// queue bounds accepted-but-not-yet-processed handshake work, while the small
	// fixed worker set bounds concurrent expensive crypto once the production
	// Noise provider is installed.
	serverEstablishmentQueueCapacity = 64
	serverEstablishmentWorkerCount   = 2
)

type serverEstablishmentJob struct {
	source       netip.AddrPort
	route        dataplane.Route
	routeDecoded bool
	length       int
	buffer       []byte
}

// serverEstablishmentExecutor owns the bounded copy/worker boundary between the
// UDP reader and a ServerEstablishmentIngress provider.
//
// TrySubmit is intentionally non-blocking. Once the provider classifier claims
// a datagram, queue or buffer-pool saturation drops that datagram instead of
// stalling the UDP reader. The client can recover through the normal handshake
// retry path.
//
// A job buffer remains owned by its worker until both provider processing and
// optional response sending complete. This permits an in-place provider to
// return a response that aliases the input buffer without racing buffer reuse.
type serverEstablishmentExecutor struct {
	ingress ServerEstablishmentIngress
	send    func([]byte, netip.AddrPort) error
	report  func(error)

	jobs chan *serverEstablishmentJob
	free chan *serverEstablishmentJob

	workers sync.WaitGroup
}

func newServerEstablishmentExecutor(
	ingress ServerEstablishmentIngress,
	maxDatagramSize int,
	queueCapacity int,
	workerCount int,
	send func([]byte, netip.AddrPort) error,
	report func(error),
) (*serverEstablishmentExecutor, error) {
	if ingress == nil {
		return nil, fmt.Errorf("server establishment ingress is nil")
	}
	if maxDatagramSize <= 0 {
		return nil, fmt.Errorf("invalid establishment datagram size %d", maxDatagramSize)
	}
	if queueCapacity < 1 {
		return nil, fmt.Errorf("invalid establishment queue capacity %d", queueCapacity)
	}
	if workerCount < 1 {
		return nil, fmt.Errorf("invalid establishment worker count %d", workerCount)
	}
	if send == nil {
		return nil, fmt.Errorf("server establishment sender is nil")
	}
	if report == nil {
		return nil, fmt.Errorf("server establishment error reporter is nil")
	}

	executor := &serverEstablishmentExecutor{
		ingress: ingress,
		send:    send,
		report:  report,
		jobs:    make(chan *serverEstablishmentJob, queueCapacity),
		free:    make(chan *serverEstablishmentJob, queueCapacity+workerCount),
	}
	for i := 0; i < queueCapacity+workerCount; i++ {
		executor.free <- &serverEstablishmentJob{
			buffer: make([]byte, maxDatagramSize),
		}
	}

	executor.workers.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go executor.runWorker()
	}

	return executor, nil
}

// TrySubmit classifies packet ownership and, for an owned establishment
// datagram, attempts to enqueue a bounded copy for asynchronous processing.
//
// owned=false means the caller may continue into encrypted dataplane admission.
// owned=true means the datagram is consumed regardless of accepted: saturation,
// oversize input or later provider rejection must never fall through to the
// dataplane.
func (e *serverEstablishmentExecutor) TrySubmit(
	source netip.AddrPort,
	route dataplane.Route,
	routeDecoded bool,
	packet []byte,
) (owned bool, accepted bool) {
	if !e.ingress.IsEstablishmentDatagram(route, routeDecoded, packet) {
		return false, false
	}

	var job *serverEstablishmentJob
	select {
	case job = <-e.free:
	default:
		return true, false
	}

	if len(packet) > len(job.buffer) {
		e.release(job)
		return true, false
	}

	job.source = source
	job.route = route
	job.routeDecoded = routeDecoded
	job.length = copy(job.buffer, packet)

	select {
	case e.jobs <- job:
		return true, true
	default:
		e.release(job)
		return true, false
	}
}

// CloseAndWait may be called only after the sole UDP submitter has stopped.
// Workers drain already accepted jobs before returning.
func (e *serverEstablishmentExecutor) CloseAndWait() {
	close(e.jobs)
	e.workers.Wait()
}

func (e *serverEstablishmentExecutor) runWorker() {
	defer e.workers.Done()

	for job := range e.jobs {
		packet := job.buffer[:job.length]
		handled, response, destination, err :=
			e.ingress.TryHandleEstablishmentDatagramInPlace(job.source, job.route, job.routeDecoded, packet)
		if err != nil {
			e.report(fmt.Errorf("server establishment ingress: %w", err))
			e.release(job)
			continue
		}
		if !handled {
			// The UDP reader already committed ownership based on the classifier.
			// Disagreement here is a local provider contract violation, not a packet
			// that may be reconsidered by the encrypted dataplane.
			e.report(fmt.Errorf(
				"server establishment ingress rejected classifier-owned datagram",
			))
			e.release(job)
			continue
		}

		if len(response) != 0 {
			if err := e.send(response, destination); err != nil {
				e.report(fmt.Errorf("send server establishment response: %w", err))
			}
		}

		e.release(job)
	}
}

func (e *serverEstablishmentExecutor) release(job *serverEstablishmentJob) {
	job.source = netip.AddrPort{}
	job.route = dataplane.Route{}
	job.routeDecoded = false
	job.length = 0
	e.free <- job
}
