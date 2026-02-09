"""
Volatility3 library runner.

Provides a clean interface to Volatility3 plugins without subprocess overhead.
Falls back gracefully when Volatility3 is not installed.

Configuration:
    Set VOLATILITY3_PATH environment variable to use an existing Volatility3
    installation. Accepts either:
      - Repo/source root:  /opt/volatility3  (contains volatility3/ package dir)
      - Site-packages dir: /opt/volatility3/.venv/lib/python3.10/site-packages

    Example:
        export VOLATILITY3_PATH="/opt/volatility3"
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Generator, Optional

logger = logging.getLogger(__name__)

# Check for external Volatility3 installation
_vol3_external_path = os.environ.get("VOLATILITY3_PATH")
if _vol3_external_path:
    _vol3_path = Path(_vol3_external_path)
    if _vol3_path.exists():
        # If path contains volatility3/ subpackage, it's a repo/source root
        # Otherwise treat it as a site-packages directory
        if (_vol3_path / "volatility3").is_dir():
            sys.path.insert(0, str(_vol3_path))
            logger.info(f"Using Volatility3 source tree: {_vol3_path}")
        else:
            sys.path.insert(0, str(_vol3_path))
            logger.info(f"Using Volatility3 from: {_vol3_path}")
    else:
        logger.warning(f"VOLATILITY3_PATH set but path not found: {_vol3_path}")

# Try to import Volatility3
try:
    from volatility3.framework import (
        automagic,
        contexts,
        interfaces,
        plugins,
    )
    from volatility3.framework.configuration import requirements
    from volatility3.framework.layers import physical, intel
    from volatility3 import framework

    VOL3_AVAILABLE = True
    VOL3_PATH = _vol3_external_path or "bundled"
except ImportError:
    VOL3_AVAILABLE = False
    VOL3_PATH = None
    contexts = None
    automagic = None

logger = logging.getLogger(__name__)


def check_volatility_available() -> None:
    """Raise ImportError if Volatility3 is not available."""
    if not VOL3_AVAILABLE:
        raise ImportError(
            "volatility3 library not installed. "
            "Install with: pip install volatility3"
        )


class Vol3Runner:
    """
    Wrapper around Volatility3 framework for running plugins.

    This class manages the Volatility3 context, automagics, and plugin
    execution. It provides structured output instead of raw TreeGrid rows.

    Usage:
        runner = Vol3Runner("/path/to/memory.raw")
        runner.initialize()

        for process in runner.run_plugin("windows.pslist.PsList"):
            print(process)
    """

    def __init__(self, image_path: str | Path):
        """
        Initialize the runner with a memory image path.

        Args:
            image_path: Path to the memory dump file
        """
        check_volatility_available()

        self.image_path = Path(image_path)
        if not self.image_path.exists():
            raise FileNotFoundError(f"Memory image not found: {image_path}")

        self._context: Optional[interfaces.context.ContextInterface] = None
        self._automagics: Optional[list] = None
        self._base_config_path = "plugins"
        self._initialized = False
        self._os_type: Optional[str] = None  # "windows", "linux", "mac"
        self._profile_info: dict[str, Any] = {}

    @property
    def is_initialized(self) -> bool:
        """Check if the runner has been initialized."""
        return self._initialized

    @property
    def os_type(self) -> Optional[str]:
        """Get detected OS type."""
        return self._os_type

    @property
    def profile_info(self) -> dict[str, Any]:
        """Get detected profile information."""
        return self._profile_info

    def initialize(self) -> dict[str, Any]:
        """
        Initialize the Volatility3 context and detect the OS profile.

        Returns:
            Profile information dict with OS details
        """
        if self._initialized:
            return self._profile_info

        logger.info(f"Initializing Volatility3 for: {self.image_path}")

        # Create the context
        self._context = contexts.Context()

        # Set up the file layer configuration
        self._context.config[
            "automagic.LayerStacker.single_location"
        ] = f"file://{self.image_path.absolute()}"

        # Get available automagics
        self._automagics = automagic.available(self._context)

        # Detect OS type by trying info plugins (automagics run per-plugin)
        self._profile_info = self._detect_profile()
        self._initialized = True

        return self._profile_info

    def _progress_callback(self, progress: float, description: str) -> None:
        """Progress callback for long-running operations."""
        # Could be used for status updates in the future
        pass

    def _detect_profile(self) -> dict[str, Any]:
        """
        Detect the OS profile by running info plugins.

        Returns:
            Dict with profile information
        """
        # Try Windows first (most common for DFIR)
        try:
            windows_info = self._try_windows_info()
            if windows_info:
                self._os_type = "windows"
                return windows_info
        except Exception as e:
            logger.debug(f"Windows detection failed: {e}")

        # Try Linux
        try:
            linux_info = self._try_linux_info()
            if linux_info:
                self._os_type = "linux"
                return linux_info
        except Exception as e:
            logger.debug(f"Linux detection failed: {e}")

        # Try Mac
        try:
            mac_info = self._try_mac_info()
            if mac_info:
                self._os_type = "mac"
                return mac_info
        except Exception as e:
            logger.debug(f"Mac detection failed: {e}")

        return {
            "os": "unknown",
            "error": "Could not detect OS profile",
        }

    def _try_windows_info(self) -> Optional[dict[str, Any]]:
        """Try to get Windows info."""
        from volatility3.plugins.windows import info as windows_info

        plugin = self._construct_plugin(windows_info.Info)
        if plugin is None:
            return None

        result = {}
        try:
            # Run the plugin
            treegrid = plugin.run()

            # Use populate() to iterate TreeGrid nodes
            def visitor(node, accumulator):
                if node.values and len(node.values) >= 2:
                    var_name = str(node.values[0])
                    var_value = str(node.values[1])
                    result[var_name] = var_value
                return None

            treegrid.populate(visitor)

            if result:
                # Extract build number from Major/Minor (e.g., "15.19041" -> "19041")
                major_minor = result.get("Major/Minor", "")
                build = major_minor.split(".")[-1] if "." in major_minor else "unknown"

                # Determine architecture
                is_64bit = result.get("Is64Bit", "").lower() == "true"

                return {
                    "os": "Windows",
                    "version": result.get("NtMajorVersion", "unknown"),
                    "build": build,
                    "arch": "x64" if is_64bit else "x86",
                    "kernel_base": result.get("Kernel Base", ""),
                    "system_time": result.get("SystemTime", ""),
                    "system_root": result.get("NtSystemRoot", ""),
                    "product_type": result.get("NtProductType", ""),
                    "processors": result.get("KeNumberProcessors", ""),
                    "raw_info": result,
                }
        except Exception as e:
            logger.debug(f"Windows info extraction failed: {e}")

        return None

    def _try_linux_info(self) -> Optional[dict[str, Any]]:
        """Try to get Linux info."""
        try:
            from volatility3.plugins.linux import banner

            plugin = self._construct_plugin(banner.Banner)
            if plugin is None:
                return None

            result = {}
            treegrid = plugin.run()

            for row in treegrid:
                if hasattr(row, '__iter__'):
                    # Extract banner info
                    pass

            if result:
                return {
                    "os": "Linux",
                    "kernel": result.get("banner", "unknown"),
                    "raw_info": result,
                }
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"Linux info extraction failed: {e}")

        return None

    def _try_mac_info(self) -> Optional[dict[str, Any]]:
        """Try to get Mac info."""
        # Mac support is less common, basic detection
        return None

    def _construct_plugin(
        self,
        plugin_class: type,
        file_handler=None,
        **kwargs
    ) -> Optional[interfaces.plugins.PluginInterface]:
        """
        Construct a plugin instance with proper configuration.

        Args:
            plugin_class: The plugin class to instantiate
            file_handler: Optional file handler for plugins that dump files
            **kwargs: Plugin-specific config options (e.g., pid, physaddr)

        Returns:
            Plugin instance or None if construction failed
        """
        if not self._context:
            return None

        try:
            # Build configuration path for this plugin
            plugin_config_path = interfaces.configuration.path_join(
                self._base_config_path,
                plugin_class.__name__,
            )

            # Apply plugin-specific parameters to the context config
            for key, value in kwargs.items():
                if value is not None:
                    config_key = f"{plugin_config_path}.{key}"
                    self._context.config[config_key] = value

            # Run automagics for this plugin
            automagic.run(
                self._automagics,
                self._context,
                plugin_class,
                plugin_config_path,
                progress_callback=self._progress_callback,
            )

            # Construct the plugin
            plugin = plugins.construct_plugin(
                self._context,
                self._automagics,
                plugin_class,
                plugin_config_path,
                self._progress_callback,
                file_handler,
            )

            return plugin

        except Exception as e:
            logger.error(f"Failed to construct plugin {plugin_class.__name__}: {e}")
            return None

    def run_plugin(
        self,
        plugin_name: str,
        output_dir: Optional[str] = None,
        **kwargs
    ) -> Generator[dict[str, Any], None, None]:
        """
        Run a Volatility3 plugin and yield structured results.

        Args:
            plugin_name: Full plugin name (e.g., "windows.pslist.PsList")
            output_dir: Directory for file output (for plugins like dumpfiles)
            **kwargs: Plugin-specific configuration

        Yields:
            Dict containing row data from the plugin
        """
        if not self._initialized:
            self.initialize()

        # Import the plugin class
        plugin_class = self._get_plugin_class(plugin_name)
        if plugin_class is None:
            raise ValueError(f"Plugin not found: {plugin_name}")

        # Create file handler CLASS if output_dir specified
        file_handler = None
        if output_dir:
            file_handler = _make_file_handler_class(output_dir)

        # Construct and run
        plugin = self._construct_plugin(plugin_class, file_handler=file_handler, **kwargs)
        if plugin is None:
            raise RuntimeError(f"Failed to construct plugin: {plugin_name}")

        # Run the plugin and convert TreeGrid to dicts
        treegrid = plugin.run()

        # Get column names from the treegrid
        columns = [col.name for col in treegrid.columns]

        # Collect rows using populate()
        rows = []

        def visitor(node, accumulator):
            row_dict = {}
            if node.values:
                for i, col_name in enumerate(columns):
                    if i < len(node.values):
                        value = node.values[i]
                        row_dict[col_name] = self._convert_value(value)
            row_dict["_tree_level"] = node.path_depth
            rows.append(row_dict)
            return None

        treegrid.populate(visitor)

        # Yield collected rows
        for row_dict in rows:
            yield row_dict

    def _get_plugin_class(self, plugin_name: str) -> Optional[type]:
        """
        Get a plugin class by name.

        Args:
            plugin_name: Full plugin name (e.g., "windows.pslist.PsList")

        Returns:
            Plugin class or None
        """
        import importlib

        try:
            parts = plugin_name.split(".")

            if len(parts) == 3:
                # Format: os.module.ClassName
                os_name, module_name, class_name = parts
                module_path = f"volatility3.plugins.{os_name}.{module_name}"

            elif len(parts) == 2:
                # Format: module.ClassName (assume current OS)
                module_name, class_name = parts
                if not self._os_type:
                    return None
                module_path = f"volatility3.plugins.{self._os_type}.{module_name}"

            else:
                return None

            # Dynamically import the module
            module = importlib.import_module(module_path)
            return getattr(module, class_name, None)

        except ImportError as e:
            logger.error(f"Failed to import plugin module {plugin_name}: {e}")
        except Exception as e:
            logger.error(f"Failed to get plugin class {plugin_name}: {e}")

        return None

    def _convert_value(self, value: Any) -> Any:
        """
        Convert Volatility3 types to standard Python types.

        Args:
            value: Value from Volatility3 TreeGrid

        Returns:
            Converted Python value
        """
        if value is None:
            return None

        # Handle Volatility renderers
        if hasattr(value, 'vol'):
            # This is a Volatility object, try to get its value
            if hasattr(value, '__int__'):
                return int(value)
            if hasattr(value, '__str__'):
                return str(value)

        # Handle NotAvailableValue
        type_name = type(value).__name__
        if "NotAvailable" in type_name or "Unreadable" in type_name:
            return None

        # Handle hex addresses
        if hasattr(value, 'vol') and hasattr(value.vol, 'offset'):
            return hex(value.vol.offset)

        # Handle datetime
        if hasattr(value, 'isoformat'):
            return value.isoformat()

        # Handle basic types
        if isinstance(value, (int, float, str, bool)):
            return value

        # Handle bytes
        if isinstance(value, bytes):
            try:
                return value.decode('utf-8', errors='replace')
            except Exception:
                return value.hex()

        # Default: convert to string
        try:
            return str(value)
        except Exception:
            return repr(value)

    def get_available_plugins(self) -> list[str]:
        """
        Get list of available plugins for the detected OS.

        Returns:
            List of plugin names
        """
        available = []

        if self._os_type == "windows":
            try:
                from volatility3.plugins import windows
                for name in dir(windows):
                    obj = getattr(windows, name)
                    if isinstance(obj, type) and hasattr(obj, 'run'):
                        available.append(f"windows.{name}")
            except ImportError:
                pass

        elif self._os_type == "linux":
            try:
                from volatility3.plugins import linux
                for name in dir(linux):
                    obj = getattr(linux, name)
                    if isinstance(obj, type) and hasattr(obj, 'run'):
                        available.append(f"linux.{name}")
            except ImportError:
                pass

        return sorted(available)


def _make_file_handler_class(output_dir: str):
    """
    Create a FileHandlerInterface subclass for vol3 file output.

    Vol3's construct_plugin() expects a CLASS (not instance) that subclasses
    FileHandlerInterface. The plugin instantiates it with a filename when
    writing files.
    """
    from volatility3.framework.interfaces.plugins import FileHandlerInterface
    import tempfile
    import os

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    class DirectFileHandler(FileHandlerInterface):
        def __init__(self, filename: str):
            fd, self._name = tempfile.mkstemp(
                suffix=".vol3", prefix="tmp_", dir=str(out_dir)
            )
            self._file = open(fd, mode="w+b")
            FileHandlerInterface.__init__(self, filename)
            for item in dir(self._file):
                if not item.startswith("_") and item not in (
                    "closed", "close", "mode", "name",
                ):
                    setattr(self, item, getattr(self._file, item))

        def __getattr__(self, item):
            return getattr(self._file, item)

        @property
        def closed(self):
            return self._file.closed

        @property
        def mode(self):
            return self._file.mode

        @property
        def name(self):
            return self._file.name

        def close(self):
            if self._file.closed:
                return
            # Compute final path
            output_filename = os.path.join(str(out_dir), self.preferred_filename)
            # Deduplicate if exists
            counter = 1
            base, ext = os.path.splitext(output_filename)
            while os.path.exists(output_filename):
                output_filename = f"{base}_{counter}{ext}"
                counter += 1
            self.preferred_filename = os.path.basename(output_filename)
            self._file.close()
            os.rename(self._name, output_filename)

    return DirectFileHandler
