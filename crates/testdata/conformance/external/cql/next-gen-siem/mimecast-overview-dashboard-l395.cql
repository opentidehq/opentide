| defineTable(query= //join delivery events with process events to filter on dangerous attachment formats
{
  #repo="mimecast" #Vendor="mimecast" #event.module="emailsecurity" #event.dataset="emailsecurity.process" #event.kind="event"
  | event.action =~! in(values=["Rej", "Hld"], ignoreCase=True) // Ignore any events where the email was held or rejected
  | case {
      // Executable file formats
      Vendor.attachments=/\.(?<dangerous_attachment_file_extension>(acm|app|application|ax|chm|com|cpl|dll|dmg|drv|efi|exe|hlp|msc|msi|msp|mui|ocx|scr|sys))\"/i;
      // Script file formats
      Vendor.attachments=/\.(?<dangerous_attachment_file_extension>(bat|cmd|csh|hta|htc|je|js|jse|ksh|ps1|ps1xml|psc1|ps2|ps2xml|psc2|py|pyc|pyo|pyz|pyzw|sh|vb|vba|vbe|vbs|ws|wsc|wsf|wsh))\"/i;
      // Shortcut file formats
      Vendor.attachments=/\.(?<dangerous_attachment_file_extension>(ink|lnk|pif|scf))\"/i;
      // Macro-enabled or suspicious document formats  (legacy MS Office formats like .doc, .xsl, or .ppt not included due to false positives concern; consider including if appropriate)
      Vendor.attachments=/\.(?<dangerous_attachment_file_extension>(docm|dot|dotm|iqy|pptm|potm|ppam|ppsm|pub|rtf|sldm|xla|xlsm|xlt|xltm|xlam))\"/i;
      // Other risky file formats
      Vendor.attachments=/\.(?<dangerous_attachment_file_extension>(html|inf|iso|img|jar|jnpl|reg|rdp|vhd|vhdx|tsp))\"/i;
  }
},    include=[Vendor.aggregateId, "Vendor.attachments", "dangerous_attachment_file_extension"], name="processed_events")

| #repo="mimecast" #Vendor="mimecast" #event.module="emailsecurity" #event.dataset="emailsecurity.delivery" #event.kind="event"
| email.direction="inbound" Vendor.delivered="true"
| match(column=Vendor.aggregateId, field=Vendor.aggregateId, include=dangerous_attachment_file_extension, file="processed_events")
| groupBy([dangerous_attachment_file_extension]) 