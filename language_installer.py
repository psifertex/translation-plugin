"""
Language installation UI for Translation plugin
"""

from binaryninja import interaction
from binaryninja.interaction import ChoiceField, TextLineField, get_form_input
from .translation_core import log
import threading


def get_available_packages():
    """Get list of available translation packages"""
    try:
        import argostranslate.package

        # Update package index
        argostranslate.package.update_package_index()

        # Get available and installed packages
        available = argostranslate.package.get_available_packages()
        installed = argostranslate.package.get_installed_packages()
        installed_keys = set(f"{pkg.from_code}_{pkg.to_code}" for pkg in installed)

        # Create list of packages not yet installed
        packages = []
        for pkg in available:
            key = f"{pkg.from_code}_{pkg.to_code}"
            if key not in installed_keys:
                packages.append({
                    'key': key,
                    'from_code': pkg.from_code,
                    'to_code': pkg.to_code,
                    'from_name': pkg.from_name,
                    'to_name': pkg.to_name,
                    'package': pkg
                })

        return packages, installed

    except ImportError:
        log.log_error("argostranslate not installed. Install with: pip install argostranslate")
        return [], []
    except Exception as e:
        log.log_error(f"Error getting available packages: {e}")
        return [], []


def get_installed_packages():
    """Get list of installed translation packages"""
    try:
        import argostranslate.package
        return argostranslate.package.get_installed_packages()
    except ImportError:
        return []
    except Exception as e:
        log.log_error(f"Error getting installed packages: {e}")
        return []


def install_package(package):
    """Install a translation package"""
    try:
        import argostranslate.package
        argostranslate.package.install_from_path(package.download())
        log.log_info("Successfully installed {} -> {}".format(package.from_name, package.to_name))
        return True
    except Exception as e:
        log.log_error("Error installing package: {}".format(e))
        return False


def uninstall_package(package):
    """Uninstall a translation package"""
    try:
        import argostranslate.package
        argostranslate.package.uninstall(package)
        log.log_info("Successfully uninstalled {} -> {}".format(package.from_name, package.to_name))
        return True
    except Exception as e:
        log.log_error("Error uninstalling package: {}".format(e))
        return False


def show_language_installer(bv=None):
    """Show the language installation UI"""
    try:
        log.log_info("Opening language installer...")

        # Get available packages
        available_packages, installed_packages = get_available_packages()

        if not available_packages and not installed_packages:
            interaction.show_message_box(
                "Translation Plugin",
                "Could not load translation packages. Make sure argostranslate is installed:\n\npip install argostranslate",
                buttons=interaction.MessageBoxButtonSet.OKButtonSet
            )
            return

        # Build menu options
        choices = []

        if available_packages:
            choices.append("=== Install New Languages ===")
            for pkg_info in available_packages:
                choices.append(f"Install: {pkg_info['from_name']} -> {pkg_info['to_name']}")

        if installed_packages:
            if choices:
                choices.append("")
            choices.append("=== Uninstall Languages ===")
            for pkg in installed_packages:
                choices.append(f"Uninstall: {pkg.from_name} -> {pkg.to_name}")

        if not choices:
            interaction.show_message_box(
                "Translation Plugin",
                "All available language packages are already installed!",
                buttons=interaction.MessageBoxButtonSet.OKButtonSet
            )
            return

        # Show choice dialog
        choice_idx = interaction.get_choice_input(
            "Language Installer",
            "Select a language package to install or uninstall:",
            choices
        )

        if choice_idx is None:
            return

        selected = choices[choice_idx]

        # Skip header rows
        if selected.startswith("===") or selected == "":
            return

        # Handle installation
        if selected.startswith("Install:"):
            # Find the package
            parts = selected.replace("Install: ", "").split(" -> ")
            from_name = parts[0]
            to_name = parts[1]

            package_to_install = None
            for pkg_info in available_packages:
                if pkg_info['from_name'] == from_name and pkg_info['to_name'] == to_name:
                    package_to_install = pkg_info['package']
                    break

            if package_to_install:
                log.log_info(f"Installing {from_name} -> {to_name}...")

                # Install in background thread
                def install_thread():
                    if install_package(package_to_install):
                        interaction.show_message_box(
                            "Translation Plugin",
                            f"Successfully installed {from_name} -> {to_name}\n\nRestart Binary Ninja to use the new language package.",
                            buttons=interaction.MessageBoxButtonSet.OKButtonSet
                        )
                    else:
                        interaction.show_message_box(
                            "Translation Plugin",
                            f"Failed to install {from_name} -> {to_name}\n\nCheck the log for details.",
                            buttons=interaction.MessageBoxButtonSet.OKButtonSet
                        )

                thread = threading.Thread(target=install_thread)
                thread.daemon = True
                thread.start()

        # Handle uninstallation
        elif selected.startswith("Uninstall:"):
            parts = selected.replace("Uninstall: ", "").split(" -> ")
            from_name = parts[0]
            to_name = parts[1]

            # Find the package
            package_to_uninstall = None
            for pkg in installed_packages:
                if pkg.from_name == from_name and pkg.to_name == to_name:
                    package_to_uninstall = pkg
                    break

            if package_to_uninstall:
                # Confirm uninstallation
                result = interaction.show_message_box(
                    "Confirm Uninstall",
                    f"Are you sure you want to uninstall {from_name} -> {to_name}?",
                    buttons=interaction.MessageBoxButtonSet.YesNoButtonSet
                )

                if result == interaction.MessageBoxButtonResult.YesButton:
                    if uninstall_package(package_to_uninstall):
                        interaction.show_message_box(
                            "Translation Plugin",
                            f"Successfully uninstalled {from_name} -> {to_name}\n\nRestart Binary Ninja to reflect the changes.",
                            buttons=interaction.MessageBoxButtonSet.OKButtonSet
                        )
                    else:
                        interaction.show_message_box(
                            "Translation Plugin",
                            f"Failed to uninstall {from_name} -> {to_name}\n\nCheck the log for details.",
                            buttons=interaction.MessageBoxButtonSet.OKButtonSet
                        )

    except Exception as e:
        log.log_error(f"Error in language installer: {e}")
        import traceback
        log.log_debug(traceback.format_exc())
