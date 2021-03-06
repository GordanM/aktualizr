
import dbus.service
import sys
from dbus.mainloop.glib import DBusGMainLoop
import gobject


class SLMService(dbus.service.Object):
    def __init__(self):
        bus_name = dbus.service.BusName('org.genivi.SoftwareLoadingManager', bus=dbus.SessionBus())        
        dbus.service.Object.__init__(self, bus_name, "/org/genivi/SoftwareLoadingManager")
   

    @dbus.service.method("org.genivi.SoftwareLoadingManager", 
                         async_callbacks=('send_reply', 'send_error'))
    def downloadComplete(self,
                          update_image,
                          signature,
                          send_reply,
                          send_error): 
            
        print('SoftwareLoadingManager.SLMService.downloadComplete(%s, %s): Called.',
                     update_image, signature)
        send_reply(True)
        fl = open("/tmp/dbustestswm.txt", 'w')
        fl.write("DownloadComplete")
        fl.close()

if __name__ == "__main__":
    DBusGMainLoop(set_as_default=True)
    mainloop = gobject.MainLoop()
    swlm_service = SLMService()
    while True:
        mainloop.run()
