// Copyright 2010 The win Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows

package win

const (
	// NOTE:  MSFTEDIT.DLL only registers MSFTEDIT_CLASS.  If an application wants
	// to use the following RichEdit classes, it needs to load riched20.dll.
	// Otherwise, CreateWindow with RICHEDIT_CLASS will fail.
	// This also applies to any dialog that uses RICHEDIT_CLASS
	// RichEdit 2.0 Window Class
	MSFTEDIT_CLASS = "RICHEDIT50W"
	RICHEDIT_CLASS = "RichEdit20W"
)

// RichEdit messages
const (
	EM_CANPASTE           = WM_USER + 50
	EM_DISPLAYBAND        = WM_USER + 51
	EM_EXGETSEL           = WM_USER + 52
	EM_EXLIMITTEXT        = WM_USER + 53
	EM_EXLINEFROMCHAR     = WM_USER + 54
	EM_EXSETSEL           = WM_USER + 55
	EM_FINDTEXT           = WM_USER + 56
	EM_FORMATRANGE        = WM_USER + 57
	EM_GETCHARFORMAT      = WM_USER + 58
	EM_GETEVENTMASK       = WM_USER + 59
	EM_GETOLEINTERFACE    = WM_USER + 60
	EM_GETPARAFORMAT      = WM_USER + 61
	EM_GETSELTEXT         = WM_USER + 62
	EM_HIDESELECTION      = WM_USER + 63
	EM_PASTESPECIAL       = WM_USER + 64
	EM_REQUESTRESIZE      = WM_USER + 65
	EM_SELECTIONTYPE      = WM_USER + 66
	EM_SETBKGNDCOLOR      = WM_USER + 67
	EM_SETCHARFORMAT      = WM_USER + 68
	EM_SETEVENTMASK       = WM_USER + 69
	EM_SETOLECALLBACK     = WM_USER + 70
	EM_SETPARAFORMAT      = WM_USER + 71
	EM_SETTARGETDEVICE    = WM_USER + 72
	EM_STREAMIN           = WM_USER + 73
	EM_STREAMOUT          = WM_USER + 74
	EM_GETTEXTRANGE       = WM_USER + 75
	EM_FINDWORDBREAK      = WM_USER + 76
	EM_SETOPTIONS         = WM_USER + 77
	EM_GETOPTIONS         = WM_USER + 78
	EM_FINDTEXTEX         = WM_USER + 79
	EM_GETWORDBREAKPROCEX = WM_USER + 80
	EM_SETWORDBREAKPROCEX = WM_USER + 81
)

// RichEdit 2.0 messages
const (
	EM_SETUNDOLIMIT    = WM_USER + 82
	EM_REDO            = WM_USER + 84
	EM_CANREDO         = WM_USER + 85
	EM_GETUNDONAME     = WM_USER + 86
	EM_GETREDONAME     = WM_USER + 87
	EM_STOPGROUPTYPING = WM_USER + 88

	EM_SETTEXTMODE = WM_USER + 89
	EM_GETTEXTMODE = WM_USER + 90
)

type TEXTMODE int

const (
	TM_PLAINTEXT       TEXTMODE = 1
	TM_RICHTEXT        TEXTMODE = 2 // Default behavior
	TM_SINGLELEVELUNDO TEXTMODE = 4
	TM_MULTILEVELUNDO  TEXTMODE = 8 // Default behavior
	TM_SINGLECODEPAGE  TEXTMODE = 16
	TM_MULTICODEPAGE   TEXTMODE = 32 // Default behavior
)

const (
	EM_AUTOURLDETECT = WM_USER + 91
)

// RichEdit 8.0 messages
const (
	AURL_ENABLEURL          = 1
	AURL_ENABLEEMAILADDR    = 2
	AURL_ENABLETELNO        = 4
	AURL_ENABLEEAURLS       = 8
	AURL_ENABLEDRIVELETTERS = 16
	AURL_DISABLEMIXEDLGC    = 32 // Disable mixed Latin Greek Cyrillic IDNs
)

const (
	EM_GETAUTOURLDETECT = WM_USER + 92
	EM_SETPALETTE       = WM_USER + 93
	EM_GETTEXTEX        = WM_USER + 94
	EM_GETTEXTLENGTHEX  = WM_USER + 95
	EM_SHOWSCROLLBAR    = WM_USER + 96
	EM_SETTEXTEX        = WM_USER + 97
)

// East Asia specific messages
const (
	EM_SETPUNCTUATION  = WM_USER + 100
	EM_GETPUNCTUATION  = WM_USER + 101
	EM_SETWORDWRAPMODE = WM_USER + 102
	EM_GETWORDWRAPMODE = WM_USER + 103
	EM_SETIMECOLOR     = WM_USER + 104
	EM_GETIMECOLOR     = WM_USER + 105
	EM_SETIMEOPTIONS   = WM_USER + 106
	EM_GETIMEOPTIONS   = WM_USER + 107
	EM_CONVPOSITION    = WM_USER + 108
)

const (
	EM_SETLANGOPTIONS = WM_USER + 120
	EM_GETLANGOPTIONS = WM_USER + 121
	EM_GETIMECOMPMODE = WM_USER + 122

	EM_FINDTEXTW   = WM_USER + 123
	EM_FINDTEXTEXW = WM_USER + 124
)

// RE3.0 FE messages
const (
	EM_RECONVERSION   = WM_USER + 125
	EM_SETIMEMODEBIAS = WM_USER + 126
	EM_GETIMEMODEBIAS = WM_USER + 127
)

// BiDi specific messages
const (
	EM_SETBIDIOPTIONS = WM_USER + 200
	EM_GETBIDIOPTIONS = WM_USER + 201

	EM_SETTYPOGRAPHYOPTIONS = WM_USER + 202
	EM_GETTYPOGRAPHYOPTIONS = WM_USER + 203
)

// Extended edit style specific messages
const (
	EM_SETEDITSTYLE = WM_USER + 204
	EM_GETEDITSTYLE = WM_USER + 205
)

// Extended edit style masks
const (
	SES_EMULATESYSEDIT    = 1
	SES_BEEPONMAXTEXT     = 2
	SES_EXTENDBACKCOLOR   = 4
	SES_MAPCPS            = 8 // Obsolete (never used)
	SES_HYPERLINKTOOLTIPS = 8
	SES_EMULATE10         = 16 // Obsolete (never used)
	SES_DEFAULTLATINLIGA  = 16
	SES_USECRLF           = 32 // Obsolete (never used)
	SES_NOFOCUSLINKNOTIFY = 32
	SES_USEAIMM           = 64
	SES_NOIME             = 128

	SES_ALLOWBEEPS         = 256
	SES_UPPERCASE          = 512
	SES_LOWERCASE          = 1024
	SES_NOINPUTSEQUENCECHK = 2048
	SES_BIDI               = 4096
	SES_SCROLLONKILLFOCUS  = 8192
	SES_XLTCRCRLFTOCR      = 16384
	SES_DRAFTMODE          = 32768

	SES_USECTF               = 0x00010000
	SES_HIDEGRIDLINES        = 0x00020000
	SES_USEATFONT            = 0x00040000
	SES_CUSTOMLOOK           = 0x00080000
	SES_LBSCROLLNOTIFY       = 0x00100000
	SES_CTFALLOWEMBED        = 0x00200000
	SES_CTFALLOWSMARTTAG     = 0x00400000
	SES_CTFALLOWPROOFING     = 0x00800000
	SES_LOGICALCARET         = 0x01000000
	SES_WORDDRAGDROP         = 0x02000000
	SES_SMARTDRAGDROP        = 0x04000000
	SES_MULTISELECT          = 0x08000000
	SES_CTFNOLOCK            = 0x10000000
	SES_NOEALINEHEIGHTADJUST = 0x20000000
	SES_MAX                  = 0x20000000
)

// Options for EM_SETLANGOPTIONS and EM_GETLANGOPTIONS
const (
	IMF_AUTOKEYBOARD        = 0x0001
	IMF_AUTOFONT            = 0x0002
	IMF_IMECANCELCOMPLETE   = 0x0004 // High completes comp string when aborting, low cancels
	IMF_IMEALWAYSSENDNOTIFY = 0x0008
	IMF_AUTOFONTSIZEADJUST  = 0x0010
	IMF_UIFONTS             = 0x0020
	IMF_NOIMPLICITLANG      = 0x0040
	IMF_DUALFONT            = 0x0080
	IMF_NOKBDLIDFIXUP       = 0x0200
	IMF_NORTFFONTSUBSTITUTE = 0x0400
	IMF_SPELLCHECKING       = 0x0800
	IMF_TKBPREDICTION       = 0x1000
	IMF_IMEUIINTEGRATION    = 0x2000
)

// Values for EM_GETIMECOMPMODE
const (
	ICM_NOTOPEN    = 0x0000
	ICM_LEVEL3     = 0x0001
	ICM_LEVEL2     = 0x0002
	ICM_LEVEL2_5   = 0x0003
	ICM_LEVEL2_SUI = 0x0004
	ICM_CTF        = 0x0005
)

// Options for EM_SETTYPOGRAPHYOPTIONS
const (
	TO_ADVANCEDTYPOGRAPHY   = 0x0001
	TO_SIMPLELINEBREAK      = 0x0002
	TO_DISABLECUSTOMTEXTOUT = 0x0004
	TO_ADVANCEDLAYOUT       = 0x0008
)

// Pegasus outline mode messages (RE 3.0)
const (
	// Outline mode message
	EM_OUTLINE = WM_USER + 220

	// Message for getting and restoring scroll pos
	EM_GETSCROLLPOS = WM_USER + 221
	EM_SETSCROLLPOS = WM_USER + 222

	// Change fontsize in current selection by wParam
	EM_SETFONTSIZE = WM_USER + 223
	EM_GETZOOM     = WM_USER + 224
	EM_SETZOOM     = WM_USER + 225
	EM_GETVIEWKIND = WM_USER + 226
	EM_SETVIEWKIND = WM_USER + 227
)

// RichEdit 4.0 messages
const (
	EM_GETPAGE          = WM_USER + 228
	EM_SETPAGE          = WM_USER + 229
	EM_GETHYPHENATEINFO = WM_USER + 230
	EM_SETHYPHENATEINFO = WM_USER + 231

	EM_GETPAGEROTATE    = WM_USER + 235
	EM_SETPAGEROTATE    = WM_USER + 236
	EM_GETCTFMODEBIAS   = WM_USER + 237
	EM_SETCTFMODEBIAS   = WM_USER + 238
	EM_GETCTFOPENSTATUS = WM_USER + 240
	EM_SETCTFOPENSTATUS = WM_USER + 241
	EM_GETIMECOMPTEXT   = WM_USER + 242
	EM_ISIME            = WM_USER + 243
	EM_GETIMEPROPERTY   = WM_USER + 244
)

// These messages control what rich edit does when it comes accross
// OLE objects during RTF stream in.  Normally rich edit queries the client
// application only after OleLoad has been called.  With these messages it is possible to
// set the rich edit control to a mode where it will query the client application before
// OleLoad is called
const (
	EM_GETQUERYRTFOBJ = WM_USER + 269
	EM_SETQUERYRTFOBJ = WM_USER + 270
)

// EM_SETPAGEROTATE wparam values
const (
	EPR_0   = 0 // Text flows left to right and top to bottom
	EPR_270 = 1 // Text flows top to bottom and right to left
	EPR_180 = 2 // Text flows right to left and bottom to top
	EPR_90  = 3 // Text flows bottom to top and left to right
	EPR_SE  = 5 // Text flows top to bottom and left to right (Mongolian text layout)
)

// EM_SETCTFMODEBIAS wparam values
const (
	CTFMODEBIAS_DEFAULT               = 0x0000
	CTFMODEBIAS_FILENAME              = 0x0001
	CTFMODEBIAS_NAME                  = 0x0002
	CTFMODEBIAS_READING               = 0x0003
	CTFMODEBIAS_DATETIME              = 0x0004
	CTFMODEBIAS_CONVERSATION          = 0x0005
	CTFMODEBIAS_NUMERIC               = 0x0006
	CTFMODEBIAS_HIRAGANA              = 0x0007
	CTFMODEBIAS_KATAKANA              = 0x0008
	CTFMODEBIAS_HANGUL                = 0x0009
	CTFMODEBIAS_HALFWIDTHKATAKANA     = 0x000A
	CTFMODEBIAS_FULLWIDTHALPHANUMERIC = 0x000B
	CTFMODEBIAS_HALFWIDTHALPHANUMERIC = 0x000C
)

// EM_SETIMEMODEBIAS lparam values
const (
	IMF_SMODE_PLAURALCLAUSE = 0x0001
	IMF_SMODE_NONE          = 0x0002
)

// EM_GETIMECOMPTEXT wparam structure
type IMECOMPTEXT struct {
	// count of bytes in the output buffer.
	Cb int32

	// value specifying the composition string type.
	//	Currently only support ICT_RESULTREADSTR
	Flags uint32
}

const ICT_RESULTREADSTR = 1

// Outline mode wparam values
const (
	// Enter normal mode,  lparam ignored
	EMO_EXIT = 0

	// Enter outline mode, lparam ignored
	EMO_ENTER = 1

	// LOWORD(lparam) == 0 ==>
	//	promote  to body-text
	// LOWORD(lparam) != 0 ==>
	//	promote/demote current selection
	//	by indicated number of levels
	EMO_PROMOTE = 2

	// HIWORD(lparam) = EMO_EXPANDSELECTION
	//	-> expands selection to level
	//	indicated in LOWORD(lparam)
	//	LOWORD(lparam) = -1/+1 corresponds
	//	to collapse/expand button presses
	//	in winword (other values are
	//	equivalent to having pressed these
	//	buttons more than once)
	//	HIWORD(lparam) = EMO_EXPANDDOCUMENT
	//	-> expands whole document to
	//	indicated level
	EMO_EXPAND = 3

	// LOWORD(lparam) != 0 -> move current
	//	selection up/down by indicated amount
	EMO_MOVESELECTION = 4

	// Returns VM_NORMAL or VM_OUTLINE
	EMO_GETVIEWMODE = 5
)

// EMO_EXPAND options
const (
	EMO_EXPANDSELECTION = 0
	EMO_EXPANDDOCUMENT  = 1
)

const (
	// Agrees with RTF \viewkindN
	VM_NORMAL = 4

	VM_OUTLINE = 2

	// Screen page view (not print layout)
	VM_PAGE = 9
)

// New messages as of Win8
const (
	EM_INSERTTABLE = WM_USER + 232
)

// Data type defining table rows for EM_INSERTTABLE
// Note: The Richedit.h is completely #pragma pack(4)-ed
type TABLEROWPARMS struct { // EM_INSERTTABLE wparam is a (TABLEROWPARMS *)
	CbRow        uint32 // Count of bytes in this structure
	CbCell       uint32 // Count of bytes in TABLECELLPARMS
	CCell        uint32 // Count of cells
	CRow         uint32 // Count of rows
	DxCellMargin int32  // Cell left/right margin (\trgaph)
	DxIndent     int32  // Row left (right if fRTL indent (similar to \trleft)
	DyHeight     int32  // Row height (\trrh)

	// nAlignment:3   Row alignment (like PARAFORMAT::bAlignment, \trql, trqr, \trqc)
	// fRTL:1         Display cells in RTL order (\rtlrow)
	// fKeep:1        Keep row together (\trkeep}
	// fKeepFollow:1  Keep row on same page as following row (\trkeepfollow)
	// fWrap:1        Wrap text to right/left (depending on bAlignment) (see \tdfrmtxtLeftN, \tdfrmtxtRightN)
	// fIdentCells:1  lparam points at single struct valid for all cells
	Flags uint32

	CpStartRow  int32  // cp where to insert table (-1 for selection cp) (can be used for either TRD by EM_GETTABLEPARMS)
	BTableLevel uint32 // Table nesting level (EM_GETTABLEPARMS only)
	ICell       uint32 // Index of cell to insert/delete (EM_SETTABLEPARMS only)
}

// Data type defining table cells for EM_INSERTTABLE
// Note: The Richedit.h is completely #pragma pack(4)-ed
type TABLECELLPARMS struct { // EM_INSERTTABLE lparam is a (TABLECELLPARMS *)
	DxWidth int32 // Cell width (\cellx)

	// nVertAlign:2   Vertical alignment (0/1/2 = top/center/bottom \clvertalt (def), \clvertalc, \clvertalb)
	// fMergeTop:1    Top cell for vertical merge (\clvmgf)
	// fMergePrev:1   Merge with cell above (\clvmrg)
	// fVertical:1    Display text top to bottom, right to left (\cltxtbrlv)
	// fMergeStart:1  Start set of horizontally merged cells (\clmgf)
	// fMergeCont:1   Merge with previous cell (\clmrg)
	Flags uint32

	WShading uint32 // Shading in .01%		(\clshdng) e.g., 10000 flips fore/back

	DxBrdrLeft   int32 // Left border width	(\clbrdrl\brdrwN) (in twips)
	DyBrdrTop    int32 // Top border width 	(\clbrdrt\brdrwN)
	DxBrdrRight  int32 // Right border width	(\clbrdrr\brdrwN)
	DyBrdrBottom int32 // Bottom border width	(\clbrdrb\brdrwN)

	CrBrdrLeft   COLORREF // Left border color	(\clbrdrl\brdrcf)
	CrBrdrTop    COLORREF // Top border color 	(\clbrdrt\brdrcf)
	CrBrdrRight  COLORREF // Right border color	(\clbrdrr\brdrcf)
	CrBrdrBottom COLORREF // Bottom border color	(\clbrdrb\brdrcf)
	CrBackPat    COLORREF // Background color 	(\clcbpat)
	CrForePat    COLORREF // Foreground color 	(\clcfpat)
}

const (
	EM_GETAUTOCORRECTPROC  = WM_USER + 233
	EM_SETAUTOCORRECTPROC  = WM_USER + 234
	EM_CALLAUTOCORRECTPROC = WM_USER + 255
)

// AutoCorrect callback
type AutoCorrectProc func(langid LANGID, pszBefore *uint16, pszAfter *uint16, cchAfter int32, pcchReplaced *int32) int

const (
	ATP_NOCHANGE       = 0
	ATP_CHANGE         = 1
	ATP_NODELIMITER    = 2
	ATP_REPLACEALLTEXT = 4
)

const (
	EM_GETTABLEPARMS = WM_USER + 265

	EM_SETEDITSTYLEEX = WM_USER + 275
	EM_GETEDITSTYLEEX = WM_USER + 276
)

// wparam values for EM_SETEDITSTYLEEX/EM_GETEDITSTYLEEX
// All unused bits are reserved.
const (
	SES_EX_NOTABLE            = 0x00000004
	SES_EX_NOMATH             = 0x00000040
	SES_EX_HANDLEFRIENDLYURL  = 0x00000100
	SES_EX_NOTHEMING          = 0x00080000
	SES_EX_NOACETATESELECTION = 0x00100000
	SES_EX_USESINGLELINE      = 0x00200000
	SES_EX_MULTITOUCH         = 0x08000000 // Only works under Win8+
	SES_EX_HIDETEMPFORMAT     = 0x10000000
	SES_EX_USEMOUSEWPARAM     = 0x20000000 // Use wParam when handling WM_MOUSEMOVE message and do not call GetAsyncKeyState
)

const (
	EM_GETSTORYTYPE = WM_USER + 290
	EM_SETSTORYTYPE = WM_USER + 291

	EM_GETELLIPSISMODE = WM_USER + 305
	EM_SETELLIPSISMODE = WM_USER + 306
)

// DWORD: *lparam for EM_GETELLIPSISMODE, lparam for EM_SETELLIPSISMODE
const (
	ELLIPSIS_MASK = 0x00000003 // all meaningful bits
	ELLIPSIS_NONE = 0x00000000 // ellipsis disabled
	ELLIPSIS_END  = 0x00000001 // ellipsis at the end (forced break)
	ELLIPSIS_WORD = 0x00000003 // ellipsis at the end (word break)
)

const (
	EM_SETTABLEPARMS = WM_USER + 307

	EM_GETTOUCHOPTIONS  = WM_USER + 310
	EM_SETTOUCHOPTIONS  = WM_USER + 311
	EM_INSERTIMAGE      = WM_USER + 314
	EM_SETUIANAME       = WM_USER + 320
	EM_GETELLIPSISSTATE = WM_USER + 322
)

// Values for EM_SETTOUCHOPTIONS/EM_GETTOUCHOPTIONS
const (
	RTO_SHOWHANDLES    = 1
	RTO_DISABLEHANDLES = 2
	RTO_READINGMODE    = 3
)

// lparam for EM_INSERTIMAGE
type RICHEDIT_IMAGE_PARAMETERS struct {
	XWidth            int32 // Units are HIMETRIC
	YHeight           int32 // Units are HIMETRIC
	Ascent            int32 // Units are HIMETRIC
	Type              int32 // Valid values are TA_TOP, TA_BOTTOM and TA_BASELINE
	PwszAlternateText *uint16
	PIStream          uintptr
}

// New notifications
const (
	EN_MSGFILTER         = 0x0700
	EN_REQUESTRESIZE     = 0x0701
	EN_SELCHANGE         = 0x0702
	EN_DROPFILES         = 0x0703
	EN_PROTECTED         = 0x0704
	EN_CORRECTTEXT       = 0x0705 // PenWin specific
	EN_STOPNOUNDO        = 0x0706
	EN_IMECHANGE         = 0x0707 // East Asia specific
	EN_SAVECLIPBOARD     = 0x0708
	EN_OLEOPFAILED       = 0x0709
	EN_OBJECTPOSITIONS   = 0x070a
	EN_LINK              = 0x070b
	EN_DRAGDROPDONE      = 0x070c
	EN_PARAGRAPHEXPANDED = 0x070d
	EN_PAGECHANGE        = 0x070e
	EN_LOWFIRTF          = 0x070f
	EN_ALIGNLTR          = 0x0710 // BiDi specific notification
	EN_ALIGNRTL          = 0x0711 // BiDi specific notification
	EN_CLIPFORMAT        = 0x0712
	EN_STARTCOMPOSITION  = 0x0713
	EN_ENDCOMPOSITION    = 0x0714
)

// Notification structure for EN_ENDCOMPOSITION
type ENDCOMPOSITIONNOTIFY struct {
	Nmhdr  NMHDR
	DwCode uint32
}

// Constants for ENDCOMPOSITIONNOTIFY dwCode
const (
	ECN_ENDCOMPOSITION = 0x0001
	ECN_NEWTEXT        = 0x0002
)

// Event notification masks
const (
	ENM_NONE              = 0x00000000
	ENM_CHANGE            = 0x00000001
	ENM_UPDATE            = 0x00000002
	ENM_SCROLL            = 0x00000004
	ENM_SCROLLEVENTS      = 0x00000008
	ENM_DRAGDROPDONE      = 0x00000010
	ENM_PARAGRAPHEXPANDED = 0x00000020
	ENM_PAGECHANGE        = 0x00000040
	ENM_CLIPFORMAT        = 0x00000080
	ENM_KEYEVENTS         = 0x00010000
	ENM_MOUSEEVENTS       = 0x00020000
	ENM_REQUESTRESIZE     = 0x00040000
	ENM_SELCHANGE         = 0x00080000
	ENM_DROPFILES         = 0x00100000
	ENM_PROTECTED         = 0x00200000
	ENM_CORRECTTEXT       = 0x00400000 // PenWin specific
	ENM_IMECHANGE         = 0x00800000 // Used by RE1.0 compatibility
	ENM_LANGCHANGE        = 0x01000000
	ENM_OBJECTPOSITIONS   = 0x02000000
	ENM_LINK              = 0x04000000
	ENM_LOWFIRTF          = 0x08000000
	ENM_STARTCOMPOSITION  = 0x10000000
	ENM_ENDCOMPOSITION    = 0x20000000
	ENM_GROUPTYPINGCHANGE = 0x40000000
	ENM_HIDELINKTOOLTIP   = 0x80000000
)

// New edit control styles
const (
	ES_SAVESEL         = 0x00008000
	ES_SUNKEN          = 0x00004000
	ES_DISABLENOSCROLL = 0x00002000
	// Same as WS_MAXIMIZE, but that doesn't make sense so we re-use the value
	ES_SELECTIONBAR = 0x01000000
	// Same as ES_UPPERCASE, but re-used to completely disable OLE drag'n'drop
	ES_NOOLEDRAGDROP = 0x00000008
)

// Obsolete Edit Style
const (
	ES_EX_NOCALLOLEINIT = 0x00000000 // Not supported in RE 2.0/3.0
)

// These flags are used in FE Windows
const (
	ES_VERTICAL = 0x00400000 // Not supported in RE 2.0/3.0
	ES_NOIME    = 0x00080000
	ES_SELFIME  = 0x00040000
)

// Edit control options
const (
	ECO_AUTOWORDSELECTION = 0x00000001
	ECO_AUTOVSCROLL       = 0x00000040
	ECO_AUTOHSCROLL       = 0x00000080
	ECO_NOHIDESEL         = 0x00000100
	ECO_READONLY          = 0x00000800
	ECO_WANTRETURN        = 0x00001000
	ECO_SAVESEL           = 0x00008000
	ECO_SELECTIONBAR      = 0x01000000
	ECO_VERTICAL          = 0x00400000 // FE specific
)

// ECO operations
const (
	ECOOP_SET = 0x0001
	ECOOP_OR  = 0x0002
	ECOOP_AND = 0x0003
	ECOOP_XOR = 0x0004
)

// New word break function actions
const (
	WB_CLASSIFY      = 3
	WB_MOVEWORDLEFT  = 4
	WB_MOVEWORDRIGHT = 5
	WB_LEFTBREAK     = 6
	WB_RIGHTBREAK    = 7
)

// East Asia specific flags
const (
	WB_MOVEWORDPREV = 4
	WB_MOVEWORDNEXT = 5
	WB_PREVBREAK    = 6
	WB_NEXTBREAK    = 7

	PC_FOLLOWING  = 1
	PC_LEADING    = 2
	PC_OVERFLOW   = 3
	PC_DELIMITER  = 4
	WBF_WORDWRAP  = 0x010
	WBF_WORDBREAK = 0x020
	WBF_OVERFLOW  = 0x040
	WBF_LEVEL1    = 0x080
	WBF_LEVEL2    = 0x100
	WBF_CUSTOM    = 0x200
)

// East Asia specific flags
const (
	IMF_FORCENONE         = 0x0001
	IMF_FORCEENABLE       = 0x0002
	IMF_FORCEDISABLE      = 0x0004
	IMF_CLOSESTATUSWINDOW = 0x0008
	IMF_VERTICAL          = 0x0020
	IMF_FORCEACTIVE       = 0x0040
	IMF_FORCEINACTIVE     = 0x0080
	IMF_FORCEREMEMBER     = 0x0100
	IMF_MULTIPLEEDIT      = 0x0400
)

// Word break flags (used with WB_CLASSIFY)
const (
	WBF_CLASS      byte = 0x0F
	WBF_ISWHITE    byte = 0x10
	WBF_BREAKLINE  byte = 0x20
	WBF_BREAKAFTER byte = 0x40
)
