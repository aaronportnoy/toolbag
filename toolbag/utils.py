from PySide import QtGui

from config import *

splash_image = options['ida_user_dir'] + os.sep + "rsrc" + os.sep + "splash.png"
pixmap = QtGui.QPixmap(splash_image)
splash = QtGui.QSplashScreen(pixmap)
splash.show()