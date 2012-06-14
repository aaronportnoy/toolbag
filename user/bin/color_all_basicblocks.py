# colors yay

import idc
import idaapi
import idautils

from PySide import QtGui


diag = QtGui.QColorDialog()

x = diag.getColor()
r,g,b,a = x.getRgb()

# ida does BGR instead of RGB
rgb = int("%02x%02x%02x" % (b, g, r), 16)

func_item = idaapi.get_func(idc.ScreenEA())

for head in idautils.Heads(func_item.startEA, func_item.endEA):
    idc.SetColor(head, idc.CIC_ITEM, rgb)

idaapi.refresh_idaview_anyway()