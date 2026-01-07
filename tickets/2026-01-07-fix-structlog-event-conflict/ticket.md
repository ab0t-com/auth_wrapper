# Bug Report for ab0t-auth Library

**File:** `ab0t_auth/logging.py`, line 132

## Issue

```
TypeError: _make_filtering_bound_logger.<locals>.make_method.<locals>.meth() got multiple values for argument 'event'
```

## Cause

The `log_auth_attempt` function is calling:

```python
logger.warning("Authentication failed", **event_data)
```

But `event_data` likely contains an `event` key, causing a conflict since the first positional argument to structlog methods is also named `event`.

## Fix Options

### Option 1: Rename the key in event_data

```python
# Before unpacking, rename 'event' to something else
if 'event' in event_data:
    event_data['auth_event'] = event_data.pop('event')
logger.warning("Authentication failed", **event_data)
```

### Option 2: Use explicit message key

```python
logger.warning(event="Authentication failed", **event_data)
```

### Option 3: Filter out conflicting keys

```python
safe_data = {k: v for k, v in event_data.items() if k != 'event'}
logger.warning("Authentication failed", **safe_data)
```

## Impact

Auth middleware crashes with 500 error instead of returning proper 401 responses when authentication fails.

## Reproduction

Enable auth middleware, send unauthenticated request to protected endpoint.
