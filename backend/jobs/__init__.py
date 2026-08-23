"""
Zenix background job processing package.

Exports:
  JobQueue — thread-backed job queue with DB persistence and stale-job recovery.
"""

from jobs.queue import JobQueue, JobNotFoundError, JobNotFinishedError

__all__ = ['JobQueue', 'JobNotFoundError', 'JobNotFinishedError']
