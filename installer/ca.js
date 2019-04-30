/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

function EvaluateWireGuardServices() {
	var inst = Session.Installer;
	var db = Session.Database;
	var view = db.OpenView("INSERT INTO `ServiceControl` (`ServiceControl`, `Name`, `Event`, `Component_`) VALUES(?, ?, ?, ?) TEMPORARY");
	var rec = inst.CreateRecord(4);
	var wsh = new ActiveXObject("WScript.Shell");
	var shl = new ActiveXObject("Shell.Application");
	var fso = new ActiveXObject("Scripting.FileSystemObject");
	var serviceKey = "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services";
	var servicePrefix = "WireGuardTunnel$";
	var serviceKeyPrefix = serviceKey + "\\" + servicePrefix;
	var allowedNameFormat = new RegExp("^[a-zA-Z0-9_=+.-]{1,32}$");
	var msiOperators = new RegExp("[=+-]", "g");
	var index = 0;

	function insertServiceControl(serviceName) {
		rec.StringData (1/*ServiceControl*/) = serviceName.replace(msiOperators, "_") + (index++).toString();
		rec.StringData (2/*Name          */) = serviceName;
		rec.IntegerData(3/*Event         */) = 0x2/*msidbServiceControlEventStop*/ | 0x20/*msidbServiceControlEventUninstallStop*/ | 0x80/*msidbServiceControlEventUninstallDelete*/ | (shl.IsServiceRunning(serviceName) ? 0x1/*msidbServiceControlEventStart*/ : 0);
		rec.StringData (4/*Component     */) = "WireGuardExecutable";

		view.Execute(rec);
	}

	insertServiceControl("WireGuardManager");

	var exe = wsh.Exec(fso.BuildPath(fso.GetSpecialFolder(1), "reg.exe") + " QUERY \"" + serviceKey + "\"");
	var lines = exe.StdOut.ReadAll().split(new RegExp("\r?\n", "g"));
	for (var i = 0; i < lines.length; ++i) {
		if (lines[i].length > serviceKeyPrefix.length && lines[i].substring(0, serviceKeyPrefix.length) == serviceKeyPrefix) {
			var tunnelName = lines[i].substring(serviceKeyPrefix.length);
			if (tunnelName.match(allowedNameFormat) != null)
				insertServiceControl(servicePrefix + tunnelName);
		}
	}
}
