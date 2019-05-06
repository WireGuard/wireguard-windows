/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

var wsh = new ActiveXObject("WScript.Shell");
var shl = new ActiveXObject("Shell.Application");
var fso = new ActiveXObject("Scripting.FileSystemObject");

function logMessage(msg) {
	var record = Installer.CreateRecord(1);
	record.StringData(0) = "WireGuard service evaluation: [1]";
	record.StringData(1) = msg.toString();
	Session.Message(0x04000000, record);
}

// I'd rather use wsh.Exec, so that we can just do ".Stdout.ReadAll()", but
// this results in a scary flashing command window. The below is the best
// workaround we can find yet. We'll keep searching for more clever tricks.
function runWithNoWindowFlash(command) {
	//TODO: Seems pretty unlikely that this temp file is secure...
	var tmpfile = fso.BuildPath(fso.GetSpecialFolder(2), fso.GetTempName());
	try {
		//TODO: Obviously cmd and tmpfile are unescaped here...
		var cmd = fso.BuildPath(fso.GetSpecialFolder(1), "cmd.exe") + " /c " + command + " > " + tmpfile;
		var ret = wsh.Run(cmd, 0, true);
		if (ret != 0) {
			logMessage("Command " + cmd + " exited with error " + ret.toString());
			return "";
		}
		var txt;
		try {
			var file = fso.OpenTextFile(tmpfile, 1);
			txt = file.ReadAll();
			file.Close();
		} catch (e) {
			logMessage("Unable to read temporary file " + tmpfile + " for command " + cmd + ": " + e.toString());
			return "";
		}
		return txt;
	} finally {
		try {
			fso.DeleteFile(tmpfile);
		} catch (e) {}
	}
}

function EvaluateWireGuardServices() {
	var inst = Session.Installer;
	var db = Session.Database;
	var view = db.OpenView("INSERT INTO `ServiceControl` (`ServiceControl`, `Name`, `Event`, `Component_`) VALUES(?, ?, ?, ?) TEMPORARY");
	var rec = inst.CreateRecord(4);
	var serviceKey = "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services";
	var servicePrefix = "WireGuardTunnel$";
	var serviceKeyPrefix = serviceKey + "\\" + servicePrefix;
	var allowedNameFormat = new RegExp("^[a-zA-Z0-9_=+.-]{1,32}$");
	var msiOperators = new RegExp("[=+-]", "g");
	var index = 0;

	function insertServiceControl(serviceName) {
		var flags = 0x2/*msidbServiceControlEventStop*/ | 0x20/*msidbServiceControlEventUninstallStop*/ | 0x80/*msidbServiceControlEventUninstallDelete*/;

		if (shl.IsServiceRunning(serviceName)) {
			flags |= 0x1/*msidbServiceControlEventStart*/;
			logMessage("Scheduling stop on upgrade/uninstall and removal on uninstall of service " + serviceName);
		} else {
			logMessage("Scheduling removal on uninstall of service " + serviceName);
		}

		rec.StringData (1/*ServiceControl*/) = serviceName.replace(msiOperators, "_") + (index++).toString();
		rec.StringData (2/*Name          */) = serviceName;
		rec.IntegerData(3/*Event         */) = flags;
		rec.StringData (4/*Component_    */) = "WireGuardExecutable";

		view.Execute(rec);
	}

	insertServiceControl("WireGuardManager");

	var txt = runWithNoWindowFlash(fso.BuildPath(fso.GetSpecialFolder(1), "reg.exe") + " query \"" + serviceKey + "\"");
	var lines = txt.split(new RegExp("\r?\n", "g"));
	for (var i = 0; i < lines.length; ++i) {
		if (lines[i].length > serviceKeyPrefix.length && lines[i].substring(0, serviceKeyPrefix.length) == serviceKeyPrefix) {
			var tunnelName = lines[i].substring(serviceKeyPrefix.length);
			if (tunnelName.match(allowedNameFormat) != null)
				insertServiceControl(servicePrefix + tunnelName);
		}
	}
}
