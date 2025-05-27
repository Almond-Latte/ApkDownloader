from enum import IntEnum, StrEnum, auto
from typing import Dict, Optional, Callable, Any
from dataclasses import dataclass
from datetime import datetime
import threading

class StatusCode(IntEnum):
    """Status codes for task execution."""
    WAITING = auto()
    PROCESSING = auto()
    SUCCESS = auto()
    STOPPED = auto()
    ERROR = auto()

class TaskCode(StrEnum):
    """Task identifiers for the APK download process."""
    SETUP_PROGRESS = "SP"
    READ_CONFIG = "RC"
    SETUP_SIGNALS = "SE"
    SETUP_LOGGER = "SL"
    MAKE_DIRS = "MDD"
    COLLECT_HASHES = "CHL"
    DOWNLOAD_APKS = "DA"

@dataclass
class TaskInfo:
    """Information about a task."""
    code: TaskCode
    name: str
    description: str
    required: bool = True
    depends_on: Optional[TaskCode] = None

@dataclass
class TaskResult:
    """Result of a task execution."""
    status: StatusCode
    message: Optional[str] = None
    error: Optional[Exception] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

class ProgressManager:
    """Manages task progress and status tracking."""
    
    # Task definitions with metadata
    TASKS = {
        TaskCode.SETUP_PROGRESS: TaskInfo(
            TaskCode.SETUP_PROGRESS, 
            "Setup Progress Display",
            "Initialize Rich progress display components"
        ),
        TaskCode.READ_CONFIG: TaskInfo(
            TaskCode.READ_CONFIG,
            "Read Configuration", 
            "Load and validate configuration parameters",
            depends_on=TaskCode.SETUP_PROGRESS
        ),
        TaskCode.SETUP_SIGNALS: TaskInfo(
            TaskCode.SETUP_SIGNALS,
            "Setup Signal Handler",
            "Configure signal handlers for graceful shutdown",
            depends_on=TaskCode.READ_CONFIG
        ),
        TaskCode.SETUP_LOGGER: TaskInfo(
            TaskCode.SETUP_LOGGER,
            "Setup Logger",
            "Initialize logging system",
            depends_on=TaskCode.SETUP_SIGNALS
        ),
        TaskCode.MAKE_DIRS: TaskInfo(
            TaskCode.MAKE_DIRS,
            "Make Download Directory",
            "Create necessary directories",
            depends_on=TaskCode.SETUP_LOGGER
        ),
        TaskCode.COLLECT_HASHES: TaskInfo(
            TaskCode.COLLECT_HASHES,
            "Collect Hash values",
            "Process APK metadata and collect hashes",
            depends_on=TaskCode.MAKE_DIRS
        ),
        TaskCode.DOWNLOAD_APKS: TaskInfo(
            TaskCode.DOWNLOAD_APKS,
            "Download APKs",
            "Download selected APK files",
            depends_on=TaskCode.COLLECT_HASHES
        ),
    }
    
    def __init__(self, status_change_callback: Optional[Callable[[TaskCode, StatusCode], None]] = None):
        """Initialize progress manager with optional status change callback."""
        self._lock = threading.RLock()
        self._task_results: Dict[TaskCode, TaskResult] = {}
        self._status_change_callback = status_change_callback
        self._initialize_tasks()
    
    def _initialize_tasks(self) -> None:
        """Initialize all tasks with WAITING status."""
        with self._lock:
            for task_code in self.TASKS:
                self._task_results[task_code] = TaskResult(StatusCode.WAITING)
    
    def start_task(self, task_code: TaskCode, message: Optional[str] = None) -> bool:
        """Start a task if dependencies are met."""
        with self._lock:
            # Check dependencies
            task_info = self.TASKS.get(task_code)
            if not task_info:
                return False
            
            if task_info.depends_on:
                dep_result = self._task_results.get(task_info.depends_on)
                if not dep_result or dep_result.status != StatusCode.SUCCESS:
                    return False
            
            # Start the task
            self._task_results[task_code] = TaskResult(
                StatusCode.PROCESSING,
                message=message,
                start_time=datetime.now()
            )
            
            self._notify_status_change(task_code, StatusCode.PROCESSING)
            return True
    
    def complete_task(self, task_code: TaskCode, status: StatusCode, 
                     message: Optional[str] = None, error: Optional[Exception] = None) -> None:
        """Complete a task with the given status."""
        with self._lock:
            current_result = self._task_results.get(task_code)
            if not current_result:
                return
            
            self._task_results[task_code] = TaskResult(
                status=status,
                message=message,
                error=error,
                start_time=current_result.start_time,
                end_time=datetime.now()
            )
            
            self._notify_status_change(task_code, status)
    
    def get_status(self, task_code: TaskCode) -> StatusCode:
        """Get the current status of a task."""
        with self._lock:
            result = self._task_results.get(task_code)
            return result.status if result else StatusCode.WAITING
    
    def get_result(self, task_code: TaskCode) -> Optional[TaskResult]:
        """Get the full result of a task."""
        with self._lock:
            return self._task_results.get(task_code)
    
    def get_all_statuses(self) -> Dict[TaskCode, StatusCode]:
        """Get all task statuses."""
        with self._lock:
            return {code: result.status for code, result in self._task_results.items()}
    
    def is_initialization_complete(self) -> bool:
        """Check if all initialization tasks are complete."""
        init_tasks = [
            TaskCode.SETUP_PROGRESS, TaskCode.READ_CONFIG, 
            TaskCode.SETUP_SIGNALS, TaskCode.SETUP_LOGGER, TaskCode.MAKE_DIRS
        ]
        return all(self.get_status(task) == StatusCode.SUCCESS for task in init_tasks)
    
    def has_failures(self) -> bool:
        """Check if any tasks have failed."""
        return any(result.status == StatusCode.ERROR for result in self._task_results.values())
    
    def get_next_pending_task(self) -> Optional[TaskCode]:
        """Get the next task that can be started."""
        with self._lock:
            for task_code, task_info in self.TASKS.items():
                current_status = self.get_status(task_code)
                if current_status != StatusCode.WAITING:
                    continue
                
                # Check dependencies
                if task_info.depends_on:
                    dep_status = self.get_status(task_info.depends_on)
                    if dep_status != StatusCode.SUCCESS:
                        continue
                
                return task_code
            return None
    
    def _notify_status_change(self, task_code: TaskCode, status: StatusCode) -> None:
        """Notify callback of status change."""
        if self._status_change_callback:
            try:
                self._status_change_callback(task_code, status)
            except Exception:
                # Ignore callback errors to prevent breaking progress tracking
                pass
    
    def get_task_info(self, task_code: TaskCode) -> Optional[TaskInfo]:
        """Get task information."""
        return self.TASKS.get(task_code)
    
    def get_execution_summary(self) -> Dict[str, Any]:
        """Get a summary of task execution."""
        with self._lock:
            summary = {
                "total_tasks": len(self.TASKS),
                "completed": 0,
                "failed": 0,
                "stopped": 0,
                "processing": 0,
                "waiting": 0,
                "tasks": {}
            }
            
            for task_code, result in self._task_results.items():
                task_info = self.TASKS[task_code]
                summary["tasks"][task_code.value] = {
                    "name": task_info.name,
                    "status": result.status.name,
                    "message": result.message,
                    "duration": self._calculate_duration(result)
                }
                
                if result.status == StatusCode.SUCCESS:
                    summary["completed"] += 1
                elif result.status == StatusCode.ERROR:
                    summary["failed"] += 1
                elif result.status == StatusCode.STOPPED:
                    summary["stopped"] += 1
                elif result.status == StatusCode.PROCESSING:
                    summary["processing"] += 1
                else:
                    summary["waiting"] += 1
            
            return summary
    
    def _calculate_duration(self, result: TaskResult) -> Optional[float]:
        """Calculate task duration in seconds."""
        if result.start_time and result.end_time:
            return (result.end_time - result.start_time).total_seconds()
        return None