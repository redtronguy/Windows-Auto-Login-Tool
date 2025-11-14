# Project Goal: Windows Auto-Login Management Tool

## Overview

This tool will be implemented as a **PowerShell-based application** using **PSDialog (Option A)** to provide a text-based, dialog-style graphical interface directly within the CLI. The interface must resemble Linux *dialog/whiptail* menus (as shown in the reference images) and must not use WinForms or WPF. All user interactions occur inside the terminal window using PSDialog menus, input boxes, and confirmation dialogs.

This tool will be implemented as a **PowerShell-based application**. It must support both a **GUI interface** and operation within a **CLI-only PowerShell session**, ensuring full functionality whether a graphical environment is available or not.

Create a Windows desktop application/client tool capable of enabling and disabling Auto-Login on Windows computers. The tool must function correctly whether the system is:

* Joined to a domain
* Not joined to a domain
* Configured to join a domain but not currently joined

The tool should provide an intuitive GUI experience with clear workflows and status reporting, as well as verbose logging for troubleshooting.

---

## Primary Features

* Detect current domain or local computer name
* Enable Auto-Login using user-specified credentials
* Disable Auto-Login by clearing or adjusting registry values
* Provide pass/fail results after each operation
* Display or provide access to verbose logs upon failure
* Clean, user-friendly GUI interaction

---

## Application Workflow

### **Startup**

1. User launches the tool.
2. User is greeted with a GUI welcome screen explaining the purpose of the tool.
3. Screen presents three options:

   * **1. Enable Auto-Login**
   * **2. Disable Auto-Login**
   * **3. Cancel**

---

## Workflow: **Cancel**

* User selects *Cancel*.
* Tool closes immediately.
* End process.

---

## Workflow: **Disable Auto-Login**

1. Tool scans for any registry keys or settings that enable Auto-Login.
2. Tool modifies or removes these values so Auto-Login is fully disabled.
3. Once complete, tool displays a status screen:

   * Success or failure
4. User presses **OK** to close the tool.
5. End process.

---

## Workflow: **Enable Auto-Login**

1. Tool scans for the current domain or local computer name.
2. Display a screen containing:

   * Domain or computer name (detected)
   * Text boxes for entering:

     * Username
     * Password
     * (Optional) Domain override
   * An **Approve** button
3. When the user approves:

   * Tool writes required registry keys to enable Auto-Login
   * Tool validates that registry operations succeeded
4. Tool displays result:

   * **Pass** → Show success message: *"Congratulations! Auto-Login is now enabled. Have a great day!"*
   * **Fail** → Display failure message with path to verbose logs for troubleshooting
5. End process.

---

## Additional Requirements

* Must handle domain vs local users gracefully
* Must log all actions to a structured log directory
* Should not leave sensitive data unencrypted where possible
* Should be robust against malformed input or incomplete domain membership

---

## Deliverables

* Fully functional GUI application
* Logging framework and documentation
* Hand-off documentation or README
* Optional: portable executable version

