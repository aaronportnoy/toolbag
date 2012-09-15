from PySide import QtGui

from config import *

if options['puffin'] == True:
	splash_image = options['ida_user_dir'] + os.sep + "rsrc" + os.sep + "splash_puffin.png"
else:
	splash_image = options['ida_user_dir'] + os.sep + "rsrc" + os.sep + "splash.png"
pixmap = QtGui.QPixmap(splash_image)
splash = QtGui.QSplashScreen(pixmap)
splash.show()