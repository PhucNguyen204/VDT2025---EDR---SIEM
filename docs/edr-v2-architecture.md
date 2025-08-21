# EDR v2 Architecture

## Overview

EDR v2 is an improved version of our endpoint detection and response system that leverages the [go-sigma-rule-engine](https://github.com/markuskont/go-sigma-rule-engine) library for more efficient and flexible rule processing.

## Key Improvements Over v1

### 1. **Native Sigma Rule Engine Integration**
- Uses the battle-tested `go-sigma-rule-engine` library
- Better performance with optimized rule matching
- Proper event interface implementation for flexible event handling

### 2. **Enhanced Event Processing**
- Dynamic event structure supporting any JSON format
- Improved field mapping for Sigma compatibility
- Support for nested field access with dot notation
- Automatic mapping of common Sigma fields to ECS format

### 3. **Better Alert Management**
- In-memory alert queue with configurable size
- Batch processing for SIEM forwarding
- Recent alerts cache for quick access
- Structured alert format with MITRE ATT&CK mapping

### 4. **Improved Performance**
- Concurrent event processing
- Efficient rule evaluation with early returns
- Reduced memory footprint
- Better resource management with proper cleanup

## Architecture Components

### Event Interface Implementation

```go
type Event struct {
    data map[string]interface{}
}

// Keywords() - Returns fields that might contain keywords
// Select() - Handles field selection with dot notation
```

### Engine Components

1. **Rule Loader**: Loads Sigma rules from directory
2. **Event Processor**: Processes incoming events against rules
3. **Alert Manager**: Manages alert queue and forwarding
4. **Statistics Tracker**: Tracks performance metrics

### Field Mapping

The engine automatically maps common Sigma fields to ECS-like fields:

- `EventID` → `event.code`
- `CommandLine` → `process.command_line`
- `Image` → `process.executable`
- `TargetUserName` → `user.name`
- `IpAddress` → `source.ip`
- And many more...

## API Endpoints

- `POST /api/v2/events` - Submit events for processing
- `GET /api/v2/stats` - Get engine statistics
- `GET /api/v2/alerts` - Retrieve recent alerts
- `GET /api/v2/rules` - List loaded rules
- `GET /health` - Health check endpoint

## Performance Considerations

Based on the go-sigma-rule-engine benchmarks:
- ~1400 ns/op for rule evaluation
- Efficient tree-based rule matching
- Minimal memory allocations

## Usage

### Starting EDR v2

```bash
# Build and run
make run-v2

# With custom parameters
./bin/edr-v2 -port 8090 -rules ./sigma/rules -log-level debug
```

### Running Demo

```bash
# Run multi-attack simulation
make demo-v2
```

## Configuration Options

- `-port`: HTTP server port (default: 8090)
- `-rules`: Sigma rules directory (default: ./sigma/rules)
- `-log-level`: Log level (default: info)
- `-siem-url`: SIEM endpoint for alert forwarding
- `-batch-size`: Alert batch size for SIEM forwarding (default: 100)
