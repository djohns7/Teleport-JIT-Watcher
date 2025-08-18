package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/types"
)

// Config holds the application configuration
type Config struct {
	AuthServer       string
	IdentityFile     string
	MaxResources     int
	CheckResources   bool
	CheckConflicts   bool
	Debug           bool
	PollInterval     time.Duration
}

// Watcher manages the access request monitoring
type Watcher struct {
	config          Config
	client          *client.Client
	lockedRequests  map[string]bool
	prodPattern     *regexp.Regexp
	researchPattern *regexp.Regexp
}

// AccessRequestInfo holds parsed information about an access request
type AccessRequestInfo struct {
	ID           string
	User         string
	Roles        []string
	Resources    []types.ResourceID
	Created      time.Time
	State        types.RequestState
}

// NewWatcher creates a new Watcher instance
func NewWatcher(config Config) (*Watcher, error) {
	// Load Machine ID identity file
	creds := client.LoadIdentityFile(config.IdentityFile)

	// Create Teleport client
	teleportClient, err := client.New(context.Background(), client.Config{
		Addrs:       []string{config.AuthServer},
		Credentials: []client.Credentials{creds},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create teleport client: %w", err)
	}

	return &Watcher{
		config:          config,
		client:          teleportClient,
		lockedRequests:  make(map[string]bool),
		prodPattern:     regexp.MustCompile(`(?i)prod`),
		researchPattern: regexp.MustCompile(`(?i)research`),
	}, nil
}

// Close cleans up the watcher
func (w *Watcher) Close() {
	w.client.Close()
	w.logInfo("Watcher closed")
}

// logInfo prints an info message
func (w *Watcher) logInfo(format string, args ...interface{}) {
	log.Printf("[INFO] "+format, args...)
}

// logDebug prints a debug message if debug mode is enabled
func (w *Watcher) logDebug(format string, args ...interface{}) {
	if w.config.Debug {
		log.Printf("[DEBUG] "+format, args...)
	}
}

// logError prints an error message
func (w *Watcher) logError(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

// parseAccessRequest converts a types.AccessRequest to our internal format
func (w *Watcher) parseAccessRequest(req types.AccessRequest) *AccessRequestInfo {
	return &AccessRequestInfo{
		ID:        req.GetName(),
		User:      req.GetUser(),
		Roles:     req.GetRoles(),
		Resources: req.GetRequestedResourceIDs(),
		Created:   req.GetCreationTime(),
		State:     req.GetState(),
	}
}

// getAllAccessRequests fetches all access requests
func (w *Watcher) getAllAccessRequests(ctx context.Context) ([]*AccessRequestInfo, error) {
	w.logDebug("Fetching all access requests")

	// Get all access requests
	filter := types.AccessRequestFilter{}
	requests, err := w.client.GetAccessRequests(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get access requests: %w", err)
	}

	w.logDebug("Successfully fetched %d access requests", len(requests))

	// Parse requests
	var parsed []*AccessRequestInfo
	for _, req := range requests {
		info := w.parseAccessRequest(req)
		parsed = append(parsed, info)
	}

	return parsed, nil
}

// getApprovedRequestsByUser groups approved requests by user
func (w *Watcher) getApprovedRequestsByUser(requests []*AccessRequestInfo) map[string][]*AccessRequestInfo {
	approved := make(map[string][]*AccessRequestInfo)

	for _, req := range requests {
		if req.State == types.RequestState_APPROVED {
			approved[req.User] = append(approved[req.User], req)
		}
	}

	// Sort each user's requests by creation time (newest first)
	for user := range approved {
		sort.Slice(approved[user], func(i, j int) bool {
			return approved[user][i].Created.After(approved[user][j].Created)
		})
	}

	return approved
}

// countResources returns the number of resources in a request
func (w *Watcher) countResources(info *AccessRequestInfo) int {
	return len(info.Resources)
}

// hasEnvironmentConflict checks if roles contain both prod and research
func (w *Watcher) hasEnvironmentConflict(roles []string) (bool, []string, []string) {
	var prodRoles, researchRoles []string

	for _, role := range roles {
		if w.prodPattern.MatchString(role) {
			prodRoles = append(prodRoles, role)
		}
		if w.researchPattern.MatchString(role) {
			researchRoles = append(researchRoles, role)
		}
	}

	hasConflict := len(prodRoles) > 0 && len(researchRoles) > 0
	return hasConflict, prodRoles, researchRoles
}

// approveAccessRequest approves a specific access request
func (w *Watcher) approveAccessRequest(ctx context.Context, requestID string, reason string) error {
	w.logDebug("Attempting to approve access request: %s", requestID)

	// Approve the request
	err := w.client.SetAccessRequestState(ctx, types.AccessRequestUpdate{
		RequestID: requestID,
		State:     types.RequestState_APPROVED,
		Reason:    reason,
	})
	if err != nil {
		return fmt.Errorf("failed to approve request: %w", err)
	}

	return nil
}

// denyAccessRequest denies a specific access request
func (w *Watcher) denyAccessRequest(ctx context.Context, requestID string, reason string) error {
	w.logDebug("Attempting to deny access request: %s", requestID)

	// Deny the request
	err := w.client.SetAccessRequestState(ctx, types.AccessRequestUpdate{
		RequestID: requestID,
		State:     types.RequestState_DENIED,
		Reason:    reason,
	})
	if err != nil {
		return fmt.Errorf("failed to deny request: %w", err)
	}

	return nil
}
func (w *Watcher) lockAccessRequest(ctx context.Context, requestID string, reason string) error {
	w.logDebug("Attempting to lock access request: %s", requestID)

	// Create lock resource
	expires := time.Now().Add(time.Hour)
	lock, err := types.NewLock("jit-watcher-"+requestID, types.LockSpecV2{
		Target: types.LockTarget{
			AccessRequest: requestID,
		},
		Message: reason,
		Expires: &expires,
	})
	if err != nil {
		return fmt.Errorf("failed to create lock: %w", err)
	}

	// Create the lock
	err = w.client.UpsertLock(ctx, lock)
	if err != nil {
		return fmt.Errorf("failed to create lock: %w", err)
	}

	w.lockedRequests[requestID] = true
	return nil
}

// validateAndProcessPendingRequests processes pending requests for auto-approval
func (w *Watcher) validateAndProcessPendingRequests(ctx context.Context, requests []*AccessRequestInfo) []*AccessRequestInfo {
	w.logInfo("=== Processing pending requests for auto-approval ===")

	var processedRequests []*AccessRequestInfo

	// Get pending requests
	var pendingRequests []*AccessRequestInfo
	for _, req := range requests {
		if req.State == types.RequestState_PENDING {
			pendingRequests = append(pendingRequests, req)
		} else {
			// Keep non-pending requests for later processing
			processedRequests = append(processedRequests, req)
		}
	}

	if len(pendingRequests) == 0 {
		w.logInfo("No pending requests found")
		return processedRequests
	}

	w.logInfo("Found %d pending requests", len(pendingRequests))

	// Process each pending request
	for _, req := range pendingRequests {
		w.logInfo("Evaluating pending request %s for user %s", req.ID, req.User)

		// Check policy violations
		resourceCount := w.countResources(req)
		hasConflict, prodRoles, researchRoles := w.hasEnvironmentConflict(req.Roles)

		var shouldApprove = true
		var denyReason string

		// Check resource limit
		if w.config.CheckResources && resourceCount > w.config.MaxResources {
			shouldApprove = false
			denyReason = fmt.Sprintf("Request contains %d resources, exceeds limit of %d", resourceCount, w.config.MaxResources)
			w.logInfo("Request %s violates resource policy: %s", req.ID, denyReason)
		}

		// Check environment conflicts
		if w.config.CheckConflicts && hasConflict {
			shouldApprove = false
			denyReason = fmt.Sprintf("Request contains conflicting environments - prod roles: %v, research roles: %v", prodRoles, researchRoles)
			w.logInfo("Request %s violates environment policy: %s", req.ID, denyReason)
		}

		// Process the request
		if shouldApprove {
			approveReason := "Auto-approved: complies with access policies"
			w.logInfo("Auto-approving request %s (%d resources)", req.ID, resourceCount)
			
			if err := w.approveAccessRequest(ctx, req.ID, approveReason); err != nil {
				w.logError("Failed to approve request %s: %v", req.ID, err)
			} else {
				w.logInfo("Successfully approved request %s", req.ID)
				// Update the request state and add to processed list
				req.State = types.RequestState_APPROVED
				processedRequests = append(processedRequests, req)
			}
		} else {
			w.logInfo("Auto-denying request %s: %s", req.ID, denyReason)
			
			if err := w.denyAccessRequest(ctx, req.ID, denyReason); err != nil {
				w.logError("Failed to deny request %s: %v", req.ID, err)
			} else {
				w.logInfo("Successfully denied request %s", req.ID)
				// Don't add denied requests to processed list
			}
		}
	}

	return processedRequests
}
// isRequestLocked checks if we've locked this request during this session
func (w *Watcher) isRequestLocked(requestID string) bool {
	return w.lockedRequests[requestID]
}

// Fix the single request environment conflict bug
func (w *Watcher) hasSingleRequestEnvironmentConflict(req *AccessRequestInfo) bool {
	if !w.config.CheckConflicts {
		return false
	}
	
	hasConflict, _, _ := w.hasEnvironmentConflict(req.Roles)
	return hasConflict
}

// hasRolePattern checks if any role matches the given pattern
func (w *Watcher) hasRolePattern(roles []string, pattern *regexp.Regexp) bool {
	for _, role := range roles {
		if pattern.MatchString(role) {
			return true
		}
	}
	return false
}

// processEnvironmentConflicts handles prod/research conflicts for a user
func (w *Watcher) processEnvironmentConflicts(ctx context.Context, userRequests []*AccessRequestInfo) []*AccessRequestInfo {
	if !w.config.CheckConflicts {
		return userRequests
	}

	if len(userRequests) == 0 {
		return userRequests
	}

	user := userRequests[0].User
	w.logInfo("Checking environment conflicts for user %s", user)

	// First, lock any single requests that have both prod and research roles
	var requestsToProcess []*AccessRequestInfo
	
	for _, req := range userRequests {
		if w.hasSingleRequestEnvironmentConflict(req) {
			// This single request has both prod and research roles - lock it
			reason := fmt.Sprintf("Single request contains both prod and research roles: %v", req.Roles)
			w.logInfo("Locking request %s: %s", req.ID, reason)
			
			if err := w.lockAccessRequest(ctx, req.ID, reason); err != nil {
				w.logError("Failed to lock conflicted request %s: %v", req.ID, err)
			} else {
				w.logInfo("Successfully locked conflicted request %s", req.ID)
			}
		} else {
			requestsToProcess = append(requestsToProcess, req)
		}
	}

	// Now handle conflicts between multiple requests
	if len(requestsToProcess) <= 1 {
		w.logInfo("After single-request conflict check: %d/%d requests remain unlocked", 
			len(requestsToProcess), len(userRequests))
		return requestsToProcess
	}

	// Collect all roles across remaining requests
	var allRoles []string
	for _, req := range requestsToProcess {
		allRoles = append(allRoles, req.Roles...)
	}

	// Check for environment conflicts between requests
	hasConflict, prodRoles, researchRoles := w.hasEnvironmentConflict(allRoles)
	if !hasConflict {
		w.logDebug("No multi-request environment conflicts found for user %s", user)
		return requestsToProcess
	}

	w.logInfo("User %s has multi-request environment conflict - prod roles: %v, research roles: %v",
		user, prodRoles, researchRoles)

	// Identify requests with conflicting roles
	var conflictRequests []*AccessRequestInfo
	for _, req := range requestsToProcess {
		hasProd := w.hasRolePattern(req.Roles, w.prodPattern)
		hasResearch := w.hasRolePattern(req.Roles, w.researchPattern)

		if hasProd || hasResearch {
			conflictRequests = append(conflictRequests, req)
		}
	}

	if len(conflictRequests) > 1 {
		// Sort by creation time (oldest first for locking)
		sort.Slice(conflictRequests, func(i, j int) bool {
			return conflictRequests[i].Created.Before(conflictRequests[j].Created)
		})

		// Lock all but the newest
		requestsToLock := conflictRequests[:len(conflictRequests)-1]
		w.logInfo("Locking %d older requests due to multi-request environment conflict", len(requestsToLock))

		for _, req := range requestsToLock {
			if w.isRequestLocked(req.ID) {
				w.logInfo("Request %s already locked", req.ID)
			} else {
				reason := "Multi-request environment conflict: user has both prod and research access across requests"
				w.logInfo("Locking request %s (created: %s, roles: %v)",
					req.ID, req.Created.Format(time.RFC3339), req.Roles)

				if err := w.lockAccessRequest(ctx, req.ID, reason); err != nil {
					w.logError("Failed to lock request %s: %v", req.ID, err)
				} else {
					w.logInfo("Successfully locked request %s for environment conflict", req.ID)
				}
			}
		}
	}

	// Return unlocked requests
	var unlockedRequests []*AccessRequestInfo
	for _, req := range requestsToProcess {
		if !w.isRequestLocked(req.ID) {
			unlockedRequests = append(unlockedRequests, req)
		}
	}

	w.logInfo("After environment conflict check: %d/%d requests remain unlocked",
		len(unlockedRequests), len(userRequests))
	return unlockedRequests
}

// processResourceLimits handles resource count limits for unlocked requests
func (w *Watcher) processResourceLimits(ctx context.Context, userRequests []*AccessRequestInfo) {
	if !w.config.CheckResources {
		return
	}

	if len(userRequests) == 0 {
		return
	}

	user := userRequests[0].User
	w.logInfo("Checking resource limits for user %s", user)

	// Count total resources
	totalResources := 0
	for _, req := range userRequests {
		totalResources += w.countResources(req)
	}

	w.logInfo("User %s has %d unlocked requests with %d total resources",
		user, len(userRequests), totalResources)

	if totalResources <= w.config.MaxResources {
		w.logDebug("User %s within resource limit (%d <= %d)",
			user, totalResources, w.config.MaxResources)
		return
	}

	w.logInfo("User %s has %d resources, need to reduce to %d",
		user, totalResources, w.config.MaxResources)

	// Keep requests until we hit the limit
	resourcesToKeep := w.config.MaxResources
	var requestsToLock []*AccessRequestInfo

	for _, req := range userRequests {
		resourceCount := w.countResources(req)

		if resourcesToKeep >= resourceCount {
			resourcesToKeep -= resourceCount
			w.logDebug("Keeping request %s with %d resources (remaining quota: %d)",
				req.ID, resourceCount, resourcesToKeep)
		} else {
			requestsToLock = append(requestsToLock, req)
			w.logDebug("Marking request %s for locking (%d resources)", req.ID, resourceCount)
		}
	}

	// Lock excess requests
	if len(requestsToLock) > 0 {
		w.logInfo("Locking %d requests to enforce resource limit", len(requestsToLock))

		for _, req := range requestsToLock {
			if w.isRequestLocked(req.ID) {
				w.logInfo("Request %s already locked", req.ID)
			} else {
				reason := fmt.Sprintf("Exceeded maximum approved resources limit (%d)", w.config.MaxResources)
				resourceNames := make([]string, len(req.Resources))
				for i, res := range req.Resources {
					resourceNames[i] = fmt.Sprintf("%s:%s", res.Kind, res.Name)
				}

				w.logInfo("Locking request %s (created: %s, %d resources: %s)",
					req.ID, req.Created.Format(time.RFC3339), len(req.Resources), strings.Join(resourceNames, ","))

				if err := w.lockAccessRequest(ctx, req.ID, reason); err != nil {
					w.logError("Failed to lock request %s: %v", req.ID, err)
				} else {
					w.logInfo("Successfully locked request %s for resource limit", req.ID)
				}
			}
		}
	}
}

// processAllUsers processes all users and their access requests
func (w *Watcher) processAllUsers(ctx context.Context) error {
	w.logInfo("=== Processing all users ===")

	// Get all access requests
	allRequests, err := w.getAllAccessRequests(ctx)
	if err != nil {
		return fmt.Errorf("failed to get access requests: %w", err)
	}

	if len(allRequests) == 0 {
		w.logInfo("No access requests found")
		return nil
	}

	w.logInfo("Found %d total access requests", len(allRequests))

	// Step 1: Process pending requests for auto-approval/denial
	processedRequests := w.validateAndProcessPendingRequests(ctx, allRequests)

	// Step 2: Group approved requests by user (after auto-approval processing)
	approvedByUser := w.getApprovedRequestsByUser(processedRequests)

	if len(approvedByUser) == 0 {
		w.logInfo("No approved requests found")
		return nil
	}

	// Step 3: Process each user's approved requests for policy enforcement
	for user, userRequests := range approvedByUser {
		w.logInfo("\n=== Processing approved requests for user: %s ===", user)

		// Check environment conflicts first
		unlockedRequests := w.processEnvironmentConflicts(ctx, userRequests)

		// Check resource limits on remaining unlocked requests
		w.processResourceLimits(ctx, unlockedRequests)
	}

	return nil
}

// Watch starts the monitoring (polling version)
func (w *Watcher) Watch(ctx context.Context) error {
	w.logInfo("Starting Teleport JIT Access Request Watcher (Polling Mode)")
	w.logInfo("Auth Service: %s", w.config.AuthServer)
	w.logInfo("Identity File: %s", w.config.IdentityFile)
	w.logInfo("Poll Interval: %s", w.config.PollInterval)

	policies := []string{}
	if w.config.CheckConflicts {
		policies = append(policies, "environment conflicts")
	}
	if w.config.CheckResources {
		policies = append(policies, fmt.Sprintf("resource limit (%d)", w.config.MaxResources))
	}
	w.logInfo("Enabled policies: %s", strings.Join(policies, ", "))

	// Test connection
	_, err := w.client.Ping(ctx)
	if err != nil {
		return fmt.Errorf("failed to ping Teleport: %w", err)
	}
	w.logInfo("Successfully connected to Teleport cluster")

	// Create ticker for polling
	ticker := time.NewTicker(w.config.PollInterval)
	defer ticker.Stop()

	// Run initial check
	w.logInfo("Running initial policy check...")
	if err := w.processAllUsers(ctx); err != nil {
		w.logError("Initial check failed: %v", err)
	}

	// Start polling loop
	for {
		select {
		case <-ctx.Done():
			w.logInfo("Context cancelled, stopping watcher")
			return ctx.Err()
		case <-ticker.C:
			w.logDebug("Running scheduled policy check...")
			if err := w.processAllUsers(ctx); err != nil {
				w.logError("Scheduled check failed: %v", err)
			}
		}
	}
}

func main() {
	// Parse command line flags
	var config Config
	flag.StringVar(&config.AuthServer, "p", "", "Teleport auth service (required, e.g., danjdemo.teleport.sh:443)")
	flag.StringVar(&config.IdentityFile, "i", "", "Path to Teleport identity file (required)")
	flag.IntVar(&config.MaxResources, "m", 3, "Maximum approved resources per user")
	flag.BoolVar(&config.CheckResources, "resource-limit", true, "Enable resource limit checking")
	flag.BoolVar(&config.CheckConflicts, "role-conflicts", true, "Enable prod/research role conflict checking")
	flag.DurationVar(&config.PollInterval, "poll-interval", 30*time.Second, "How often to check for policy violations")
	flag.BoolVar(&config.Debug, "d", false, "Enable debug output")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Teleport JIT Access Request Watcher - Polling-based monitoring and policy enforcement\n\n")
		fmt.Fprintf(os.Stderr, "Required arguments:\n")
		fmt.Fprintf(os.Stderr, "  -p string\n")
		fmt.Fprintf(os.Stderr, "        Teleport auth service (e.g., danjdemo.teleport.sh:443)\n")
		fmt.Fprintf(os.Stderr, "  -i string\n")
		fmt.Fprintf(os.Stderr, "        Path to Teleport identity file\n\n")
		fmt.Fprintf(os.Stderr, "Optional arguments:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Run with both policies (default, check every 30s)\n")
		fmt.Fprintf(os.Stderr, "  %s -p danjdemo.teleport.sh:443 -i ./identity\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Check every 10 seconds with debug output\n")
		fmt.Fprintf(os.Stderr, "  %s -p danjdemo.teleport.sh:443 -i ./identity -poll-interval=10s -d\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Run only environment conflict checking\n")
		fmt.Fprintf(os.Stderr, "  %s -p danjdemo.teleport.sh:443 -i ./identity -resource-limit=false\n", os.Args[0])
	}

	flag.Parse()

	// Validate required arguments
	if config.AuthServer == "" {
		fmt.Fprintf(os.Stderr, "Error: Auth service is required (-p option)\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if config.IdentityFile == "" {
		fmt.Fprintf(os.Stderr, "Error: Identity file is required (-i option)\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// Validate identity file exists
	if _, err := os.Stat(config.IdentityFile); os.IsNotExist(err) {
		log.Fatalf("Identity file does not exist: %s", config.IdentityFile)
	}

	// Validate max resources
	if config.MaxResources < 1 {
		log.Fatalf("Max resources must be a positive integer, got: %d", config.MaxResources)
	}

	// Validate poll interval
	if config.PollInterval < time.Second {
		log.Fatalf("Poll interval must be at least 1 second, got: %s", config.PollInterval)
	}

	// Create watcher
	watcher, err := NewWatcher(config)
	if err != nil {
		log.Fatalf("Failed to create watcher: %v", err)
	}
	defer watcher.Close()

	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start watcher in a goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- watcher.Watch(ctx)
	}()

	// Wait for either completion or signal
	select {
	case err := <-errChan:
		if err != nil && err != context.Canceled {
			log.Fatalf("Watcher failed: %v", err)
		}
	case sig := <-sigChan:
		log.Printf("Received signal %v, shutting down...", sig)
		cancel()

		// Wait for graceful shutdown or timeout
		select {
		case <-errChan:
			log.Println("Watcher stopped gracefully")
		case <-time.After(5 * time.Second):
			log.Println("Timeout waiting for graceful shutdown")
		}
	}

	log.Println("JIT Access Request Watcher completed successfully")
}
