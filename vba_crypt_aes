Option Compare Database
Option Explicit

' As found http://stackoverflow.com/a/170018/5738
Private Const clOneMask = 16515072          '000000 111111 111111 111111
Private Const clTwoMask = 258048            '111111 000000 111111 111111
Private Const clThreeMask = 4032            '111111 111111 000000 111111
Private Const clFourMask = 63               '111111 111111 111111 000000

Private Const clHighMask = 16711680         '11111111 00000000 00000000
Private Const clMidMask = 65280             '00000000 11111111 00000000
Private Const clLowMask = 255               '00000000 00000000 11111111

Private Const cl2Exp18 = 262144             '2 to the 18th power
Private Const cl2Exp12 = 4096               '2 to the 12th
Private Const cl2Exp6 = 64                  '2 to the 6th
Private Const cl2Exp8 = 256                 '2 to the 8th
Private Const cl2Exp16 = 65536              '2 to the 16th

' This is all as per: http://stackoverflow.com/a/482150/5738 - License CC-BY 3.0
' ############################## Content from StackOverflow Answer START

' Based on: http://vb.wikia.com/wiki/SHA-1.bas
Private Type FourBytes
    A As Byte
    B As Byte
    C As Byte
    D As Byte
End Type
Private Type OneLong
    L As Long
End Type

' Dependency on "functions Base64" and "functions SHA1" and "GenerateSalt"
Public Function StoreEncryptAES(sPlainText As String, sPassword As String, Optional iRounds As Integer = 2000) As String
    Dim sSaltedPassword As String
    Dim sSalt As String
    Dim sSaltedAESEncryptedPasswort As String

    sSalt = GenerateSalt
    sSaltedPassword = sPassword & sSalt

    sSaltedAESEncryptedPasswort = Encode64(EncryptAES(SHA1HASH(sPlainText) & ":" & sPlainText, sSaltedPassword, iRounds))

    StoreEncryptAES = sSaltedAESEncryptedPasswort & sSalt
End Function

' Dependency on "functions Base64" and "functions SHA1"
Public Function RetrieveDecryptAES(sCipherText As String, sPassword As String, Optional iRounds As Integer = 2000, Optional asString As Boolean = False) As String
    Dim dMessage As String
    Dim hash As String
    Dim separator As Integer
    Dim sSalt As String
    Dim sSaltedAESEncryptedMessage As String
    Dim sSaltedPassword As String
    
    sSalt = Right(sCipherText, 16)
    sSaltedAESEncryptedMessage = Left(sCipherText, Len(sCipherText) - 16)
    sSaltedPassword = sPassword & sSalt
    
    dMessage = DecryptAES(Decode64(sSaltedAESEncryptedMessage), sSaltedPassword, iRounds)
    If InStr(dMessage, ":") < 1 Then
        If asString = True Then
            RetrieveDecryptAES = "#invalidpassword"
        Else
            'Err.Raise 640, "functions AES", "Invalid password/passphrase"
            RetrieveDecryptAES = "wrong Password"
            Exit Function
        End If
    End If
    hash = Left(dMessage, InStr(dMessage, ":") - 1)
    RetrieveDecryptAES = Right(dMessage, Len(dMessage) - (Len(hash) + 1))
    If hash <> SHA1HASH(RetrieveDecryptAES) Then
        If asString = True Then
            RetrieveDecryptAES = "#invalidpassword"
        Else
            'Err.Raise 640, "functions AES", "Invalid password/passphrase"
            RetrieveDecryptAES = "wrong Password"
            Exit Function
        End If
    End If
End Function

Private Function EncryptAES(sMessage As String, sPassword As String, Optional iRounds As Integer = 1) As String
    EncryptAES = sMessage
    Do Until iRounds < 1
        EncryptAES = AES(EncryptAES, True, sPassword)
        iRounds = iRounds - 1
    Loop
End Function

Private Function DecryptAES(sMessage As String, sPassword As String, Optional iRounds As Integer = 1) As String
    DecryptAES = sMessage
    Do Until iRounds < 1
        DecryptAES = AES(DecryptAES, False, sPassword)
        iRounds = iRounds - 1
    Loop
    DecryptAES = nTrim2(DecryptAES)
End Function

' ###########################################################################################
' # Following code performs AES Encryption/Decryption of text
' #
' # Based on :
' # http://bytes.com/topic/access/insights/906850-aes-encryption-algorithm-vba-vbscript
' # With adjustments based on :
' # http://bytes.com/topic/access/answers/940196-help-aes-encryption-algorithm-vba-vbscript
' ###########################################################################################

Private Function AES(sMessage As String, isEncode As Boolean, sPassword As String) As String
    Dim sbox()
    Dim sboxinv()
    Dim rcon()
    Dim g2()
    Dim g3()
    Dim g9()
    Dim g11()
    Dim g13()
    Dim g14()

    g2 = Array( _
        &H0, &H2, &H4, &H6, &H8, &HA, &HC, &HE, &H10, &H12, &H14, &H16, &H18, &H1A, &H1C, &H1E, _
        &H20, &H22, &H24, &H26, &H28, &H2A, &H2C, &H2E, &H30, &H32, &H34, &H36, &H38, &H3A, &H3C, &H3E, _
        &H40, &H42, &H44, &H46, &H48, &H4A, &H4C, &H4E, &H50, &H52, &H54, &H56, &H58, &H5A, &H5C, &H5E, _
        &H60, &H62, &H64, &H66, &H68, &H6A, &H6C, &H6E, &H70, &H72, &H74, &H76, &H78, &H7A, &H7C, &H7E, _
        &H80, &H82, &H84, &H86, &H88, &H8A, &H8C, &H8E, &H90, &H92, &H94, &H96, &H98, &H9A, &H9C, &H9E, _
        &HA0, &HA2, &HA4, &HA6, &HA8, &HAA, &HAC, &HAE, &HB0, &HB2, &HB4, &HB6, &HB8, &HBA, &HBC, &HBE, _
        &HC0, &HC2, &HC4, &HC6, &HC8, &HCA, &HCC, &HCE, &HD0, &HD2, &HD4, &HD6, &HD8, &HDA, &HDC, &HDE, _
        &HE0, &HE2, &HE4, &HE6, &HE8, &HEA, &HEC, &HEE, &HF0, &HF2, &HF4, &HF6, &HF8, &HFA, &HFC, &HFE, _
        &H1B, &H19, &H1F, &H1D, &H13, &H11, &H17, &H15, &HB, &H9, &HF, &HD, &H3, &H1, &H7, &H5, _
        &H3B, &H39, &H3F, &H3D, &H33, &H31, &H37, &H35, &H2B, &H29, &H2F, &H2D, &H23, &H21, &H27, &H25, _
        &H5B, &H59, &H5F, &H5D, &H53, &H51, &H57, &H55, &H4B, &H49, &H4F, &H4D, &H43, &H41, &H47, &H45, _
        &H7B, &H79, &H7F, &H7D, &H73, &H71, &H77, &H75, &H6B, &H69, &H6F, &H6D, &H63, &H61, &H67, &H65, _
        &H9B, &H99, &H9F, &H9D, &H93, &H91, &H97, &H95, &H8B, &H89, &H8F, &H8D, &H83, &H81, &H87, &H85, _
        &HBB, &HB9, &HBF, &HBD, &HB3, &HB1, &HB7, &HB5, &HAB, &HA9, &HAF, &HAD, &HA3, &HA1, &HA7, &HA5, _
        &HDB, &HD9, &HDF, &HDD, &HD3, &HD1, &HD7, &HD5, &HCB, &HC9, &HCF, &HCD, &HC3, &HC1, &HC7, &HC5, _
        &HFB, &HF9, &HFF, &HFD, &HF3, &HF1, &HF7, &HF5, &HEB, &HE9, &HEF, &HED, &HE3, &HE1, &HE7, &HE5)

    g3 = Array( _
        &H0, &H3, &H6, &H5, &HC, &HF, &HA, &H9, &H18, &H1B, &H1E, &H1D, &H14, &H17, &H12, &H11, _
        &H30, &H33, &H36, &H35, &H3C, &H3F, &H3A, &H39, &H28, &H2B, &H2E, &H2D, &H24, &H27, &H22, &H21, _
        &H60, &H63, &H66, &H65, &H6C, &H6F, &H6A, &H69, &H78, &H7B, &H7E, &H7D, &H74, &H77, &H72, &H71, _
        &H50, &H53, &H56, &H55, &H5C, &H5F, &H5A, &H59, &H48, &H4B, &H4E, &H4D, &H44, &H47, &H42, &H41, _
        &HC0, &HC3, &HC6, &HC5, &HCC, &HCF, &HCA, &HC9, &HD8, &HDB, &HDE, &HDD, &HD4, &HD7, &HD2, &HD1, _
        &HF0, &HF3, &HF6, &HF5, &HFC, &HFF, &HFA, &HF9, &HE8, &HEB, &HEE, &HED, &HE4, &HE7, &HE2, &HE1, _
        &HA0, &HA3, &HA6, &HA5, &HAC, &HAF, &HAA, &HA9, &HB8, &HBB, &HBE, &HBD, &HB4, &HB7, &HB2, &HB1, _
        &H90, &H93, &H96, &H95, &H9C, &H9F, &H9A, &H99, &H88, &H8B, &H8E, &H8D, &H84, &H87, &H82, &H81, _
        &H9B, &H98, &H9D, &H9E, &H97, &H94, &H91, &H92, &H83, &H80, &H85, &H86, &H8F, &H8C, &H89, &H8A, _
        &HAB, &HA8, &HAD, &HAE, &HA7, &HA4, &HA1, &HA2, &HB3, &HB0, &HB5, &HB6, &HBF, &HBC, &HB9, &HBA, _
        &HFB, &HF8, &HFD, &HFE, &HF7, &HF4, &HF1, &HF2, &HE3, &HE0, &HE5, &HE6, &HEF, &HEC, &HE9, &HEA, _
        &HCB, &HC8, &HCD, &HCE, &HC7, &HC4, &HC1, &HC2, &HD3, &HD0, &HD5, &HD6, &HDF, &HDC, &HD9, &HDA, _
        &H5B, &H58, &H5D, &H5E, &H57, &H54, &H51, &H52, &H43, &H40, &H45, &H46, &H4F, &H4C, &H49, &H4A, _
        &H6B, &H68, &H6D, &H6E, &H67, &H64, &H61, &H62, &H73, &H70, &H75, &H76, &H7F, &H7C, &H79, &H7A, _
        &H3B, &H38, &H3D, &H3E, &H37, &H34, &H31, &H32, &H23, &H20, &H25, &H26, &H2F, &H2C, &H29, &H2A, _
        &HB, &H8, &HD, &HE, &H7, &H4, &H1, &H2, &H13, &H10, &H15, &H16, &H1F, &H1C, &H19, &H1A)

    g9 = Array( _
        &H0, &H9, &H12, &H1B, &H24, &H2D, &H36, &H3F, &H48, &H41, &H5A, &H53, &H6C, &H65, &H7E, &H77, _
        &H90, &H99, &H82, &H8B, &HB4, &HBD, &HA6, &HAF, &HD8, &HD1, &HCA, &HC3, &HFC, &HF5, &HEE, &HE7, _
        &H3B, &H32, &H29, &H20, &H1F, &H16, &HD, &H4, &H73, &H7A, &H61, &H68, &H57, &H5E, &H45, &H4C, _
        &HAB, &HA2, &HB9, &HB0, &H8F, &H86, &H9D, &H94, &HE3, &HEA, &HF1, &HF8, &HC7, &HCE, &HD5, &HDC, _
        &H76, &H7F, &H64, &H6D, &H52, &H5B, &H40, &H49, &H3E, &H37, &H2C, &H25, &H1A, &H13, &H8, &H1, _
        &HE6, &HEF, &HF4, &HFD, &HC2, &HCB, &HD0, &HD9, &HAE, &HA7, &HBC, &HB5, &H8A, &H83, &H98, &H91, _
        &H4D, &H44, &H5F, &H56, &H69, &H60, &H7B, &H72, &H5, &HC, &H17, &H1E, &H21, &H28, &H33, &H3A, _
        &HDD, &HD4, &HCF, &HC6, &HF9, &HF0, &HEB, &HE2, &H95, &H9C, &H87, &H8E, &HB1, &HB8, &HA3, &HAA, _
        &HEC, &HE5, &HFE, &HF7, &HC8, &HC1, &HDA, &HD3, &HA4, &HAD, &HB6, &HBF, &H80, &H89, &H92, &H9B, _
        &H7C, &H75, &H6E, &H67, &H58, &H51, &H4A, &H43, &H34, &H3D, &H26, &H2F, &H10, &H19, &H2, &HB, _
        &HD7, &HDE, &HC5, &HCC, &HF3, &HFA, &HE1, &HE8, &H9F, &H96, &H8D, &H84, &HBB, &HB2, &HA9, &HA0, _
        &H47, &H4E, &H55, &H5C, &H63, &H6A, &H71, &H78, &HF, &H6, &H1D, &H14, &H2B, &H22, &H39, &H30, _
        &H9A, &H93, &H88, &H81, &HBE, &HB7, &HAC, &HA5, &HD2, &HDB, &HC0, &HC9, &HF6, &HFF, &HE4, &HED, _
        &HA, &H3, &H18, &H11, &H2E, &H27, &H3C, &H35, &H42, &H4B, &H50, &H59, &H66, &H6F, &H74, &H7D, _
        &HA1, &HA8, &HB3, &HBA, &H85, &H8C, &H97, &H9E, &HE9, &HE0, &HFB, &HF2, &HCD, &HC4, &HDF, &HD6, _
        &H31, &H38, &H23, &H2A, &H15, &H1C, &H7, &HE, &H79, &H70, &H6B, &H62, &H5D, &H54, &H4F, &H46)

    g11 = Array( _
        &H0, &HB, &H16, &H1D, &H2C, &H27, &H3A, &H31, &H58, &H53, &H4E, &H45, &H74, &H7F, &H62, &H69, _
        &HB0, &HBB, &HA6, &HAD, &H9C, &H97, &H8A, &H81, &HE8, &HE3, &HFE, &HF5, &HC4, &HCF, &HD2, &HD9, _
        &H7B, &H70, &H6D, &H66, &H57, &H5C, &H41, &H4A, &H23, &H28, &H35, &H3E, &HF, &H4, &H19, &H12, _
        &HCB, &HC0, &HDD, &HD6, &HE7, &HEC, &HF1, &HFA, &H93, &H98, &H85, &H8E, &HBF, &HB4, &HA9, &HA2, _
        &HF6, &HFD, &HE0, &HEB, &HDA, &HD1, &HCC, &HC7, &HAE, &HA5, &HB8, &HB3, &H82, &H89, &H94, &H9F, _
        &H46, &H4D, &H50, &H5B, &H6A, &H61, &H7C, &H77, &H1E, &H15, &H8, &H3, &H32, &H39, &H24, &H2F, _
        &H8D, &H86, &H9B, &H90, &HA1, &HAA, &HB7, &HBC, &HD5, &HDE, &HC3, &HC8, &HF9, &HF2, &HEF, &HE4, _
        &H3D, &H36, &H2B, &H20, &H11, &H1A, &H7, &HC, &H65, &H6E, &H73, &H78, &H49, &H42, &H5F, &H54, _
        &HF7, &HFC, &HE1, &HEA, &HDB, &HD0, &HCD, &HC6, &HAF, &HA4, &HB9, &HB2, &H83, &H88, &H95, &H9E, _
        &H47, &H4C, &H51, &H5A, &H6B, &H60, &H7D, &H76, &H1F, &H14, &H9, &H2, &H33, &H38, &H25, &H2E, _
        &H8C, &H87, &H9A, &H91, &HA0, &HAB, &HB6, &HBD, &HD4, &HDF, &HC2, &HC9, &HF8, &HF3, &HEE, &HE5, _
        &H3C, &H37, &H2A, &H21, &H10, &H1B, &H6, &HD, &H64, &H6F, &H72, &H79, &H48, &H43, &H5E, &H55, _
        &H1, &HA, &H17, &H1C, &H2D, &H26, &H3B, &H30, &H59, &H52, &H4F, &H44, &H75, &H7E, &H63, &H68, _
        &HB1, &HBA, &HA7, &HAC, &H9D, &H96, &H8B, &H80, &HE9, &HE2, &HFF, &HF4, &HC5, &HCE, &HD3, &HD8, _
        &H7A, &H71, &H6C, &H67, &H56, &H5D, &H40, &H4B, &H22, &H29, &H34, &H3F, &HE, &H5, &H18, &H13, _
        &HCA, &HC1, &HDC, &HD7, &HE6, &HED, &HF0, &HFB, &H92, &H99, &H84, &H8F, &HBE, &HB5, &HA8, &HA3)

    g13 = Array( _
        &H0, &HD, &H1A, &H17, &H34, &H39, &H2E, &H23, &H68, &H65, &H72, &H7F, &H5C, &H51, &H46, &H4B, _
        &HD0, &HDD, &HCA, &HC7, &HE4, &HE9, &HFE, &HF3, &HB8, &HB5, &HA2, &HAF, &H8C, &H81, &H96, &H9B, _
        &HBB, &HB6, &HA1, &HAC, &H8F, &H82, &H95, &H98, &HD3, &HDE, &HC9, &HC4, &HE7, &HEA, &HFD, &HF0, _
        &H6B, &H66, &H71, &H7C, &H5F, &H52, &H45, &H48, &H3, &HE, &H19, &H14, &H37, &H3A, &H2D, &H20, _
        &H6D, &H60, &H77, &H7A, &H59, &H54, &H43, &H4E, &H5, &H8, &H1F, &H12, &H31, &H3C, &H2B, &H26, _
        &HBD, &HB0, &HA7, &HAA, &H89, &H84, &H93, &H9E, &HD5, &HD8, &HCF, &HC2, &HE1, &HEC, &HFB, &HF6, _
        &HD6, &HDB, &HCC, &HC1, &HE2, &HEF, &HF8, &HF5, &HBE, &HB3, &HA4, &HA9, &H8A, &H87, &H90, &H9D, _
        &H6, &HB, &H1C, &H11, &H32, &H3F, &H28, &H25, &H6E, &H63, &H74, &H79, &H5A, &H57, &H40, &H4D, _
        &HDA, &HD7, &HC0, &HCD, &HEE, &HE3, &HF4, &HF9, &HB2, &HBF, &HA8, &HA5, &H86, &H8B, &H9C, &H91, _
        &HA, &H7, &H10, &H1D, &H3E, &H33, &H24, &H29, &H62, &H6F, &H78, &H75, &H56, &H5B, &H4C, &H41, _
        &H61, &H6C, &H7B, &H76, &H55, &H58, &H4F, &H42, &H9, &H4, &H13, &H1E, &H3D, &H30, &H27, &H2A, _
        &HB1, &HBC, &HAB, &HA6, &H85, &H88, &H9F, &H92, &HD9, &HD4, &HC3, &HCE, &HED, &HE0, &HF7, &HFA, _
        &HB7, &HBA, &HAD, &HA0, &H83, &H8E, &H99, &H94, &HDF, &HD2, &HC5, &HC8, &HEB, &HE6, &HF1, &HFC, _
        &H67, &H6A, &H7D, &H70, &H53, &H5E, &H49, &H44, &HF, &H2, &H15, &H18, &H3B, &H36, &H21, &H2C, _
        &HC, &H1, &H16, &H1B, &H38, &H35, &H22, &H2F, &H64, &H69, &H7E, &H73, &H50, &H5D, &H4A, &H47, _
        &HDC, &HD1, &HC6, &HCB, &HE8, &HE5, &HF2, &HFF, &HB4, &HB9, &HAE, &HA3, &H80, &H8D, &H9A, &H97)

    g14 = Array( _
        &H0, &HE, &H1C, &H12, &H38, &H36, &H24, &H2A, &H70, &H7E, &H6C, &H62, &H48, &H46, &H54, &H5A, _
        &HE0, &HEE, &HFC, &HF2, &HD8, &HD6, &HC4, &HCA, &H90, &H9E, &H8C, &H82, &HA8, &HA6, &HB4, &HBA, _
        &HDB, &HD5, &HC7, &HC9, &HE3, &HED, &HFF, &HF1, &HAB, &HA5, &HB7, &HB9, &H93, &H9D, &H8F, &H81, _
        &H3B, &H35, &H27, &H29, &H3, &HD, &H1F, &H11, &H4B, &H45, &H57, &H59, &H73, &H7D, &H6F, &H61, _
        &HAD, &HA3, &HB1, &HBF, &H95, &H9B, &H89, &H87, &HDD, &HD3, &HC1, &HCF, &HE5, &HEB, &HF9, &HF7, _
        &H4D, &H43, &H51, &H5F, &H75, &H7B, &H69, &H67, &H3D, &H33, &H21, &H2F, &H5, &HB, &H19, &H17, _
        &H76, &H78, &H6A, &H64, &H4E, &H40, &H52, &H5C, &H6, &H8, &H1A, &H14, &H3E, &H30, &H22, &H2C, _
        &H96, &H98, &H8A, &H84, &HAE, &HA0, &HB2, &HBC, &HE6, &HE8, &HFA, &HF4, &HDE, &HD0, &HC2, &HCC, _
        &H41, &H4F, &H5D, &H53, &H79, &H77, &H65, &H6B, &H31, &H3F, &H2D, &H23, &H9, &H7, &H15, &H1B, _
        &HA1, &HAF, &HBD, &HB3, &H99, &H97, &H85, &H8B, &HD1, &HDF, &HCD, &HC3, &HE9, &HE7, &HF5, &HFB, _
        &H9A, &H94, &H86, &H88, &HA2, &HAC, &HBE, &HB0, &HEA, &HE4, &HF6, &HF8, &HD2, &HDC, &HCE, &HC0, _
        &H7A, &H74, &H66, &H68, &H42, &H4C, &H5E, &H50, &HA, &H4, &H16, &H18, &H32, &H3C, &H2E, &H20, _
        &HEC, &HE2, &HF0, &HFE, &HD4, &HDA, &HC8, &HC6, &H9C, &H92, &H80, &H8E, &HA4, &HAA, &HB8, &HB6, _
        &HC, &H2, &H10, &H1E, &H34, &H3A, &H28, &H26, &H7C, &H72, &H60, &H6E, &H44, &H4A, &H58, &H56, _
        &H37, &H39, &H2B, &H25, &HF, &H1, &H13, &H1D, &H47, &H49, &H5B, &H55, &H7F, &H71, &H63, &H6D, _
        &HD7, &HD9, &HCB, &HC5, &HEF, &HE1, &HF3, &HFD, &HA7, &HA9, &HBB, &HB5, &H9F, &H91, &H83, &H8D)

    sbox = Array( _
        &H63, &H7C, &H77, &H7B, &HF2, &H6B, &H6F, &HC5, &H30, &H1, &H67, &H2B, &HFE, &HD7, &HAB, &H76, _
        &HCA, &H82, &HC9, &H7D, &HFA, &H59, &H47, &HF0, &HAD, &HD4, &HA2, &HAF, &H9C, &HA4, &H72, &HC0, _
        &HB7, &HFD, &H93, &H26, &H36, &H3F, &HF7, &HCC, &H34, &HA5, &HE5, &HF1, &H71, &HD8, &H31, &H15, _
        &H4, &HC7, &H23, &HC3, &H18, &H96, &H5, &H9A, &H7, &H12, &H80, &HE2, &HEB, &H27, &HB2, &H75, _
        &H9, &H83, &H2C, &H1A, &H1B, &H6E, &H5A, &HA0, &H52, &H3B, &HD6, &HB3, &H29, &HE3, &H2F, &H84, _
        &H53, &HD1, &H0, &HED, &H20, &HFC, &HB1, &H5B, &H6A, &HCB, &HBE, &H39, &H4A, &H4C, &H58, &HCF, _
        &HD0, &HEF, &HAA, &HFB, &H43, &H4D, &H33, &H85, &H45, &HF9, &H2, &H7F, &H50, &H3C, &H9F, &HA8, _
        &H51, &HA3, &H40, &H8F, &H92, &H9D, &H38, &HF5, &HBC, &HB6, &HDA, &H21, &H10, &HFF, &HF3, &HD2, _
        &HCD, &HC, &H13, &HEC, &H5F, &H97, &H44, &H17, &HC4, &HA7, &H7E, &H3D, &H64, &H5D, &H19, &H73, _
        &H60, &H81, &H4F, &HDC, &H22, &H2A, &H90, &H88, &H46, &HEE, &HB8, &H14, &HDE, &H5E, &HB, &HDB, _
        &HE0, &H32, &H3A, &HA, &H49, &H6, &H24, &H5C, &HC2, &HD3, &HAC, &H62, &H91, &H95, &HE4, &H79, _
        &HE7, &HC8, &H37, &H6D, &H8D, &HD5, &H4E, &HA9, &H6C, &H56, &HF4, &HEA, &H65, &H7A, &HAE, &H8, _
        &HBA, &H78, &H25, &H2E, &H1C, &HA6, &HB4, &HC6, &HE8, &HDD, &H74, &H1F, &H4B, &HBD, &H8B, &H8A, _
        &H70, &H3E, &HB5, &H66, &H48, &H3, &HF6, &HE, &H61, &H35, &H57, &HB9, &H86, &HC1, &H1D, &H9E, _
        &HE1, &HF8, &H98, &H11, &H69, &HD9, &H8E, &H94, &H9B, &H1E, &H87, &HE9, &HCE, &H55, &H28, &HDF, _
        &H8C, &HA1, &H89, &HD, &HBF, &HE6, &H42, &H68, &H41, &H99, &H2D, &HF, &HB0, &H54, &HBB, &H16)

    sboxinv = Array( _
        &H52, &H9, &H6A, &HD5, &H30, &H36, &HA5, &H38, &HBF, &H40, &HA3, &H9E, &H81, &HF3, &HD7, &HFB, _
        &H7C, &HE3, &H39, &H82, &H9B, &H2F, &HFF, &H87, &H34, &H8E, &H43, &H44, &HC4, &HDE, &HE9, &HCB, _
        &H54, &H7B, &H94, &H32, &HA6, &HC2, &H23, &H3D, &HEE, &H4C, &H95, &HB, &H42, &HFA, &HC3, &H4E, _
        &H8, &H2E, &HA1, &H66, &H28, &HD9, &H24, &HB2, &H76, &H5B, &HA2, &H49, &H6D, &H8B, &HD1, &H25, _
        &H72, &HF8, &HF6, &H64, &H86, &H68, &H98, &H16, &HD4, &HA4, &H5C, &HCC, &H5D, &H65, &HB6, &H92, _
        &H6C, &H70, &H48, &H50, &HFD, &HED, &HB9, &HDA, &H5E, &H15, &H46, &H57, &HA7, &H8D, &H9D, &H84, _
        &H90, &HD8, &HAB, &H0, &H8C, &HBC, &HD3, &HA, &HF7, &HE4, &H58, &H5, &HB8, &HB3, &H45, &H6, _
        &HD0, &H2C, &H1E, &H8F, &HCA, &H3F, &HF, &H2, &HC1, &HAF, &HBD, &H3, &H1, &H13, &H8A, &H6B, _
        &H3A, &H91, &H11, &H41, &H4F, &H67, &HDC, &HEA, &H97, &HF2, &HCF, &HCE, &HF0, &HB4, &HE6, &H73, _
        &H96, &HAC, &H74, &H22, &HE7, &HAD, &H35, &H85, &HE2, &HF9, &H37, &HE8, &H1C, &H75, &HDF, &H6E, _
        &H47, &HF1, &H1A, &H71, &H1D, &H29, &HC5, &H89, &H6F, &HB7, &H62, &HE, &HAA, &H18, &HBE, &H1B, _
        &HFC, &H56, &H3E, &H4B, &HC6, &HD2, &H79, &H20, &H9A, &HDB, &HC0, &HFE, &H78, &HCD, &H5A, &HF4, _
        &H1F, &HDD, &HA8, &H33, &H88, &H7, &HC7, &H31, &HB1, &H12, &H10, &H59, &H27, &H80, &HEC, &H5F, _
        &H60, &H51, &H7F, &HA9, &H19, &HB5, &H4A, &HD, &H2D, &HE5, &H7A, &H9F, &H93, &HC9, &H9C, &HEF, _
        &HA0, &HE0, &H3B, &H4D, &HAE, &H2A, &HF5, &HB0, &HC8, &HEB, &HBB, &H3C, &H83, &H53, &H99, &H61, _
        &H17, &H2B, &H4, &H7E, &HBA, &H77, &HD6, &H26, &HE1, &H69, &H14, &H63, &H55, &H21, &HC, &H7D)

    rcon = Array( _
        &H8D, &H1, &H2, &H4, &H8, &H10, &H20, &H40, &H80, &H1B, &H36, &H6C, &HD8, &HAB, &H4D, &H9A, _
        &H2F, &H5E, &HBC, &H63, &HC6, &H97, &H35, &H6A, &HD4, &HB3, &H7D, &HFA, &HEF, &HC5, &H91, &H39, _
        &H72, &HE4, &HD3, &HBD, &H61, &HC2, &H9F, &H25, &H4A, &H94, &H33, &H66, &HCC, &H83, &H1D, &H3A, _
        &H74, &HE8, &HCB, &H8D, &H1, &H2, &H4, &H8, &H10, &H20, &H40, &H80, &H1B, &H36, &H6C, &HD8, _
        &HAB, &H4D, &H9A, &H2F, &H5E, &HBC, &H63, &HC6, &H97, &H35, &H6A, &HD4, &HB3, &H7D, &HFA, &HEF, _
        &HC5, &H91, &H39, &H72, &HE4, &HD3, &HBD, &H61, &HC2, &H9F, &H25, &H4A, &H94, &H33, &H66, &HCC, _
        &H83, &H1D, &H3A, &H74, &HE8, &HCB, &H8D, &H1, &H2, &H4, &H8, &H10, &H20, &H40, &H80, &H1B, _
        &H36, &H6C, &HD8, &HAB, &H4D, &H9A, &H2F, &H5E, &HBC, &H63, &HC6, &H97, &H35, &H6A, &HD4, &HB3, _
        &H7D, &HFA, &HEF, &HC5, &H91, &H39, &H72, &HE4, &HD3, &HBD, &H61, &HC2, &H9F, &H25, &H4A, &H94, _
        &H33, &H66, &HCC, &H83, &H1D, &H3A, &H74, &HE8, &HCB, &H8D, &H1, &H2, &H4, &H8, &H10, &H20, _
        &H40, &H80, &H1B, &H36, &H6C, &HD8, &HAB, &H4D, &H9A, &H2F, &H5E, &HBC, &H63, &HC6, &H97, &H35, _
        &H6A, &HD4, &HB3, &H7D, &HFA, &HEF, &HC5, &H91, &H39, &H72, &HE4, &HD3, &HBD, &H61, &HC2, &H9F, _
        &H25, &H4A, &H94, &H33, &H66, &HCC, &H83, &H1D, &H3A, &H74, &HE8, &HCB, &H8D, &H1, &H2, &H4, _
        &H8, &H10, &H20, &H40, &H80, &H1B, &H36, &H6C, &HD8, &HAB, &H4D, &H9A, &H2F, &H5E, &HBC, &H63, _
        &HC6, &H97, &H35, &H6A, &HD4, &HB3, &H7D, &HFA, &HEF, &HC5, &H91, &H39, &H72, &HE4, &HD3, &HBD, _
        &H61, &HC2, &H9F, &H25, &H4A, &H94, &H33, &H66, &HCC, &H83, &H1D, &H3A, &H74, &HE8, &HCB)

    Dim expandedKey, block(16), aesKey(32), i, isDone, j
    Dim sPlain, sPass, sCipher, sTemp, nonce(16), priorCipher(16)
    Dim x, r, y, temp(4), intTemp

    For i = 0 To 15
        nonce(i) = 0
    Next

    For i = 0 To (Len(sPassword) - 1)
        aesKey(i) = Asc(Mid(sPassword, i + 1, 1))
    Next

    For i = Len(sPassword) To 31
        aesKey(i) = 0
    Next

    expandedKey = expandKey(aesKey, sbox, rcon)

    sPlain = sMessage
    sCipher = ""
    j = 0
    isDone = False

    Do Until isDone
        sTemp = Mid(sPlain, j * 16 + 1, 16)

        If Len(sTemp) < 16 Then
            For i = Len(sTemp) To 15
                sTemp = sTemp & Chr(0)
            Next
        End If

        For i = 0 To 15
            block(i) = Asc(Mid(sTemp, (i Mod 4) * 4 + (i \ 4) + 1, 1))
        Next

        If (j + 1) * 16 >= Len(sPlain) Then
            isDone = True
        End If

        j = j + 1

        If isEncode Then
            r = 0
            For i = 0 To 15
                block(i) = block(i) Xor nonce(i) Xor expandedKey((i Mod 4) * 4 + (i \ 4))
            Next

            For x = 1 To 13
                block(0) = sbox(block(0))
                block(1) = sbox(block(1))
                block(2) = sbox(block(2))
                block(3) = sbox(block(3))

                intTemp = sbox(block(4))
                block(4) = sbox(block(5))
                block(5) = sbox(block(6))
                block(6) = sbox(block(7))
                block(7) = intTemp

                intTemp = sbox(block(8))
                block(8) = sbox(block(10))
                block(10) = intTemp
                intTemp = sbox(block(9))
                block(9) = sbox(block(11))
                block(11) = intTemp

                intTemp = sbox(block(12))
                block(12) = sbox(block(15))
                block(15) = sbox(block(14))
                block(14) = sbox(block(13))
                block(13) = intTemp

                r = x * 16
                For i = 0 To 3
                    temp(0) = block(i)
                    temp(1) = block(i + 4)
                    temp(2) = block(i + 8)
                    temp(3) = block(i + 12)

                    block(i) = g2(temp(0)) Xor temp(3) Xor temp(2) Xor g3(temp(1)) Xor expandedKey(r + i * 4)
                    block(i + 4) = g2(temp(1)) Xor temp(0) Xor temp(3) Xor g3(temp(2)) Xor expandedKey(r + i * 4 + 1)
                    block(i + 8) = g2(temp(2)) Xor temp(1) Xor temp(0) Xor g3(temp(3)) Xor expandedKey(r + i * 4 + 2)
                    block(i + 12) = g2(temp(3)) Xor temp(2) Xor temp(1) Xor g3(temp(0)) Xor expandedKey(r + i * 4 + 3)
                Next
            Next

            block(0) = sbox(block(0)) Xor expandedKey(224)
            block(1) = sbox(block(1)) Xor expandedKey(228)
            block(2) = sbox(block(2)) Xor expandedKey(232)
            block(3) = sbox(block(3)) Xor expandedKey(236)

            intTemp = sbox(block(4)) Xor expandedKey(237)
            block(4) = sbox(block(5)) Xor expandedKey(225)
            block(5) = sbox(block(6)) Xor expandedKey(229)
            block(6) = sbox(block(7)) Xor expandedKey(233)
            block(7) = intTemp

            intTemp = sbox(block(8)) Xor expandedKey(234)
            block(8) = sbox(block(10)) Xor expandedKey(226)
            block(10) = intTemp
            intTemp = sbox(block(9)) Xor expandedKey(238)
            block(9) = sbox(block(11)) Xor expandedKey(230)
            block(11) = intTemp

            intTemp = sbox(block(12)) Xor expandedKey(231)
            block(12) = sbox(block(15)) Xor expandedKey(227)
            block(15) = sbox(block(14)) Xor expandedKey(239)
            block(14) = sbox(block(13)) Xor expandedKey(235)
            block(13) = intTemp

            For i = 0 To 15
                nonce(i) = block(i)
            Next
        Else
            For i = 0 To 15
                priorCipher(i) = block(i)
            Next

            block(0) = sboxinv(block(0) Xor expandedKey(224))
            block(1) = sboxinv(block(1) Xor expandedKey(228))
            block(2) = sboxinv(block(2) Xor expandedKey(232))
            block(3) = sboxinv(block(3) Xor expandedKey(236))

            intTemp = sboxinv(block(4) Xor expandedKey(225))
            block(4) = sboxinv(block(7) Xor expandedKey(237))
            block(7) = sboxinv(block(6) Xor expandedKey(233))
            block(6) = sboxinv(block(5) Xor expandedKey(229))
            block(5) = intTemp

            intTemp = sboxinv(block(8) Xor expandedKey(226))
            block(8) = sboxinv(block(10) Xor expandedKey(234))
            block(10) = intTemp
            intTemp = sboxinv(block(9) Xor expandedKey(230))
            block(9) = sboxinv(block(11) Xor expandedKey(238))
            block(11) = intTemp

            intTemp = sboxinv(block(12) Xor expandedKey(227))
            block(12) = sboxinv(block(13) Xor expandedKey(231))
            block(13) = sboxinv(block(14) Xor expandedKey(235))
            block(14) = sboxinv(block(15) Xor expandedKey(239))
            block(15) = intTemp

            For x = 13 To 1 Step -1
                r = x * 16

                For i = 0 To 3
                    temp(0) = block(i) Xor expandedKey(r + i * 4)
                    temp(1) = block(i + 4) Xor expandedKey(r + i * 4 + 1)
                    temp(2) = block(i + 8) Xor expandedKey(r + i * 4 + 2)
                    temp(3) = block(i + 12) Xor expandedKey(r + i * 4 + 3)

                    block(i) = g14(temp(0)) Xor g9(temp(3)) Xor g13(temp(2)) Xor g11(temp(1))
                    block(i + 4) = g14(temp(1)) Xor g9(temp(0)) Xor g13(temp(3)) Xor g11(temp(2))
                    block(i + 8) = g14(temp(2)) Xor g9(temp(1)) Xor g13(temp(0)) Xor g11(temp(3))
                    block(i + 12) = g14(temp(3)) Xor g9(temp(2)) Xor g13(temp(1)) Xor g11(temp(0))
                Next

                block(0) = sboxinv(block(0))
                block(1) = sboxinv(block(1))
                block(2) = sboxinv(block(2))
                block(3) = sboxinv(block(3))

                intTemp = sboxinv(block(4))
                block(4) = sboxinv(block(7))
                block(7) = sboxinv(block(6))
                block(6) = sboxinv(block(5))
                block(5) = intTemp

                intTemp = sboxinv(block(8))
                block(8) = sboxinv(block(10))
                block(10) = intTemp
                intTemp = sboxinv(block(9))
                block(9) = sboxinv(block(11))
                block(11) = intTemp

                intTemp = sboxinv(block(12))
                block(12) = sboxinv(block(13))
                block(13) = sboxinv(block(14))
                block(14) = sboxinv(block(15))
                block(15) = intTemp
            Next

            r = 0
            For i = 0 To 15
                block(i) = block(i) Xor expandedKey((i Mod 4) * 4 + (i \ 4)) Xor nonce(i)
                nonce(i) = priorCipher(i)
            Next
        End If

        For i = 0 To 15
            sCipher = sCipher & Chr(block((i Mod 4) * 4 + (i \ 4)))
        Next
    Loop

    AES = sCipher
End Function

Private Function keyScheduleCore(ByRef row(), ByVal A, ByRef sbox(), ByRef rcon())
    Dim Result(4), i

    For i = 0 To 3
        Result(i) = sbox(row((i + 5) Mod 4))
    Next

    Result(0) = Result(0) Xor rcon(A)
    keyScheduleCore = Result
End Function

Private Function expandKey(ByRef key(), ByRef sbox(), ByRef rcon())
    Dim rConIter, temp(), i, Result(240)

    ReDim temp(4)
    rConIter = 1

    For i = 0 To 31
        Result(i) = key(i)
    Next

    For i = 32 To 239 Step 4
        temp(0) = Result(i - 4)
        temp(1) = Result(i - 3)
        temp(2) = Result(i - 2)
        temp(3) = Result(i - 1)

        If i Mod 32 = 0 Then
            temp = keyScheduleCore(temp, rConIter, sbox, rcon)
            rConIter = rConIter + 1
        End If

        If i Mod 32 = 16 Then
            temp(0) = sbox(temp(0))
            temp(1) = sbox(temp(1))
            temp(2) = sbox(temp(2))
            temp(3) = sbox(temp(3))
        End If

        Result(i) = Result(i - 32) Xor temp(0)
        Result(i + 1) = Result(i - 31) Xor temp(1)
        Result(i + 2) = Result(i - 30) Xor temp(2)
        Result(i + 3) = Result(i - 29) Xor temp(3)
    Next

    expandKey = Result
End Function

' ###########################################################################################
' # Following code trims null (chr(0)) characters from a string
' #
' # Based on :
' # http://stackoverflow.com/a/30760913/5738
' ###########################################################################################

Private Function nTrim2(theString As String) As String
    Dim iPos As Long
    iPos = Len(theString)
    Dim i As Integer
    For i = iPos To 0 Step -1
        iPos = i
        If Mid$(theString, i, 1) <> Chr$(0) Then Exit For
    Next
    nTrim2 = Left$(theString, iPos)
End Function

' As found http://stackoverflow.com/a/170018/5738
Private Function Encode64(sString As String) As String

    Dim bTrans(63) As Byte, lPowers8(255) As Long, lPowers16(255) As Long, bOut() As Byte, bIn() As Byte
    Dim lChar As Long, lTrip As Long, iPad As Integer, lLen As Long, lTemp As Long, lPos As Long, lOutSize As Long

    For lTemp = 0 To 63                                 'Fill the translation table.
        Select Case lTemp
            Case 0 To 25
                bTrans(lTemp) = 65 + lTemp              'A - Z
            Case 26 To 51
                bTrans(lTemp) = 71 + lTemp              'a - z
            Case 52 To 61
                bTrans(lTemp) = lTemp - 4               '1 - 0
            Case 62
                bTrans(lTemp) = 43                      'Chr(43) = "+"
            Case 63
                bTrans(lTemp) = 47                      'Chr(47) = "/"
        End Select
    Next lTemp

    For lTemp = 0 To 255                                'Fill the 2^8 and 2^16 lookup tables.
        lPowers8(lTemp) = lTemp * cl2Exp8
        lPowers16(lTemp) = lTemp * cl2Exp16
    Next lTemp

    iPad = Len(sString) Mod 3                           'See if the length is divisible by 3
    If iPad Then                                        'If not, figure out the end pad and resize the input.
        iPad = 3 - iPad
        sString = sString & String(iPad, Chr(0))
    End If

    bIn = StrConv(sString, vbFromUnicode)               'Load the input string.
    lLen = ((UBound(bIn) + 1) \ 3) * 4                  'Length of resulting string.
    lTemp = lLen \ 72                                   'Added space for vbCrLfs.
    lOutSize = ((lTemp * 2) + lLen) - 1                 'Calculate the size of the output buffer.
    ReDim bOut(lOutSize)                                'Make the output buffer.

    lLen = 0                                            'Reusing this one, so reset it.

    For lChar = LBound(bIn) To UBound(bIn) Step 3
        lTrip = lPowers16(bIn(lChar)) + lPowers8(bIn(lChar + 1)) + bIn(lChar + 2)    'Combine the 3 bytes
        lTemp = lTrip And clOneMask                     'Mask for the first 6 bits
        bOut(lPos) = bTrans(lTemp \ cl2Exp18)           'Shift it down to the low 6 bits and get the value
        lTemp = lTrip And clTwoMask                     'Mask for the second set.
        bOut(lPos + 1) = bTrans(lTemp \ cl2Exp12)       'Shift it down and translate.
        lTemp = lTrip And clThreeMask                   'Mask for the third set.
        bOut(lPos + 2) = bTrans(lTemp \ cl2Exp6)        'Shift it down and translate.
        bOut(lPos + 3) = bTrans(lTrip And clFourMask)   'Mask for the low set.
        If lLen = 68 Then                               'Ready for a newline
            bOut(lPos + 4) = 13                         'Chr(13) = vbCr
            bOut(lPos + 5) = 10                         'Chr(10) = vbLf
            lLen = 0                                    'Reset the counter
            lPos = lPos + 6
        Else
            lLen = lLen + 4
            lPos = lPos + 4
        End If
    Next lChar

    If bOut(lOutSize) = 10 Then lOutSize = lOutSize - 2 'Shift the padding chars down if it ends with CrLf.

    If iPad = 1 Then                                    'Add the padding chars if any.
        bOut(lOutSize) = 61                             'Chr(61) = "="
    ElseIf iPad = 2 Then
        bOut(lOutSize) = 61
        bOut(lOutSize - 1) = 61
    End If

    Encode64 = StrConv(bOut, vbUnicode)                 'Convert back to a string and return it.

End Function

Private Function Decode64(sString As String) As String
    Dim bOut() As Byte, bIn() As Byte, bTrans(255) As Byte, lPowers6(63) As Long, lPowers12(63) As Long
    Dim lPowers18(63) As Long, lQuad As Long, iPad As Integer, lChar As Long, lPos As Long, sOut As String
    Dim lTemp As Long

    sString = Replace(sString, vbCr, vbNullString)      'Get rid of the vbCrLfs.  These could be in...
    sString = Replace(sString, vbLf, vbNullString)      'either order.

    lTemp = Len(sString) Mod 4                          'Test for valid input.
    If lTemp Then
        Exit Function
        'Call Err.Raise(vbObjectError, "MyDecode", "Input string is not valid Base64.")
    End If

    If InStrRev(sString, "==") Then                     'InStrRev is faster when you know it's at the end.
        iPad = 2                                        'Note:  These translate to 0, so you can leave them...
    ElseIf InStrRev(sString, "=") Then                  'in the string and just resize the output.
        iPad = 1
    End If

    For lTemp = 0 To 255                                'Fill the translation table.
        Select Case lTemp
            Case 65 To 90
                bTrans(lTemp) = lTemp - 65              'A - Z
            Case 97 To 122
                bTrans(lTemp) = lTemp - 71              'a - z
            Case 48 To 57
                bTrans(lTemp) = lTemp + 4               '1 - 0
            Case 43
                bTrans(lTemp) = 62                      'Chr(43) = "+"
            Case 47
                bTrans(lTemp) = 63                      'Chr(47) = "/"
        End Select
    Next lTemp

    For lTemp = 0 To 63                                 'Fill the 2^6, 2^12, and 2^18 lookup tables.
        lPowers6(lTemp) = lTemp * cl2Exp6
        lPowers12(lTemp) = lTemp * cl2Exp12
        lPowers18(lTemp) = lTemp * cl2Exp18
    Next lTemp

    bIn = StrConv(sString, vbFromUnicode)               'Load the input byte array.
    ReDim bOut((((UBound(bIn) + 1) \ 4) * 3) - 1)       'Prepare the output buffer.

    For lChar = 0 To UBound(bIn) Step 4
        lQuad = lPowers18(bTrans(bIn(lChar))) + lPowers12(bTrans(bIn(lChar + 1))) + _
                lPowers6(bTrans(bIn(lChar + 2))) + bTrans(bIn(lChar + 3))           'Rebuild the bits.
        lTemp = lQuad And clHighMask                    'Mask for the first byte
        bOut(lPos) = lTemp \ cl2Exp16                   'Shift it down
        lTemp = lQuad And clMidMask                     'Mask for the second byte
        bOut(lPos + 1) = lTemp \ cl2Exp8                'Shift it down
        bOut(lPos + 2) = lQuad And clLowMask            'Mask for the third byte
        lPos = lPos + 3
    Next lChar

    sOut = StrConv(bOut, vbUnicode)                     'Convert back to a string.
    If iPad Then sOut = Left$(sOut, Len(sOut) - iPad)   'Chop off any extra bytes.
    Decode64 = sOut
End Function

' This is all as per: http://stackoverflow.com/a/482150/5738 - License CC-BY 3.0
' ############################## Content from StackOverflow Answer START

' Based on: http://vb.wikia.com/wiki/SHA-1.bas
Private Function HexDefaultSHA1(message() As Byte) As String
    Dim H1 As Long, H2 As Long, H3 As Long, H4 As Long, H5 As Long
    DefaultSHA1 message, H1, H2, H3, H4, H5
    HexDefaultSHA1 = DecToHex5(H1, H2, H3, H4, H5)
End Function

Private Function HexSHA1(message() As Byte, ByVal Key1 As Long, ByVal Key2 As Long, ByVal Key3 As Long, ByVal Key4 As Long) As String
    Dim H1 As Long, H2 As Long, H3 As Long, H4 As Long, H5 As Long
    xSHA1 message, Key1, Key2, Key3, Key4, H1, H2, H3, H4, H5
    HexSHA1 = DecToHex5(H1, H2, H3, H4, H5)
End Function

Private Sub DefaultSHA1(message() As Byte, H1 As Long, H2 As Long, H3 As Long, H4 As Long, H5 As Long)
    xSHA1 message, &H5A827999, &H6ED9EBA1, &H8F1BBCDC, &HCA62C1D6, H1, H2, H3, H4, H5
End Sub

Private Sub xSHA1(message() As Byte, ByVal Key1 As Long, ByVal Key2 As Long, ByVal Key3 As Long, ByVal Key4 As Long, H1 As Long, H2 As Long, H3 As Long, H4 As Long, H5 As Long)
    'CA62C1D68F1BBCDC6ED9EBA15A827999 + "abc" = "A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D"
    '"abc" = "A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D"

    Dim U As Long, P As Long
    Dim FB As FourBytes, OL As OneLong
    Dim i As Integer
    Dim W(80) As Long
    Dim A As Long, B As Long, C As Long, D As Long, E As Long
    Dim T As Long

    H1 = &H67452301: H2 = &HEFCDAB89: H3 = &H98BADCFE: H4 = &H10325476: H5 = &HC3D2E1F0

    U = UBound(message) + 1: OL.L = U32ShiftLeft3(U): A = U \ &H20000000: LSet FB = OL 'U32ShiftRight29(U)

    ReDim Preserve message(0 To (U + 8 And -64) + 63)
    message(U) = 128

    U = UBound(message)
    message(U - 4) = A
    message(U - 3) = FB.D
    message(U - 2) = FB.C
    message(U - 1) = FB.B
    message(U) = FB.A

    While P < U
        For i = 0 To 15
            FB.D = message(P)
            FB.C = message(P + 1)
            FB.B = message(P + 2)
            FB.A = message(P + 3)
            LSet OL = FB
            W(i) = OL.L
            P = P + 4
        Next i

        For i = 16 To 79
            W(i) = U32RotateLeft1(W(i - 3) Xor W(i - 8) Xor W(i - 14) Xor W(i - 16))
        Next i

        A = H1: B = H2: C = H3: D = H4: E = H5

        For i = 0 To 19
            T = U32Add(U32Add(U32Add(U32Add(U32RotateLeft5(A), E), W(i)), Key1), ((B And C) Or ((Not B) And D)))
            E = D: D = C: C = U32RotateLeft30(B): B = A: A = T
        Next i
        For i = 20 To 39
            T = U32Add(U32Add(U32Add(U32Add(U32RotateLeft5(A), E), W(i)), Key2), (B Xor C Xor D))
            E = D: D = C: C = U32RotateLeft30(B): B = A: A = T
        Next i
        For i = 40 To 59
            T = U32Add(U32Add(U32Add(U32Add(U32RotateLeft5(A), E), W(i)), Key3), ((B And C) Or (B And D) Or (C And D)))
            E = D: D = C: C = U32RotateLeft30(B): B = A: A = T
        Next i
        For i = 60 To 79
            T = U32Add(U32Add(U32Add(U32Add(U32RotateLeft5(A), E), W(i)), Key4), (B Xor C Xor D))
            E = D: D = C: C = U32RotateLeft30(B): B = A: A = T
        Next i

        H1 = U32Add(H1, A): H2 = U32Add(H2, B): H3 = U32Add(H3, C): H4 = U32Add(H4, D): H5 = U32Add(H5, E)
    Wend
End Sub

Private Function U32Add(ByVal A As Long, ByVal B As Long) As Long
    If (A Xor B) < 0 Then
        U32Add = A + B
    Else
        U32Add = (A Xor &H80000000) + B Xor &H80000000
    End If
End Function

Private Function U32ShiftLeft3(ByVal A As Long) As Long
    U32ShiftLeft3 = (A And &HFFFFFFF) * 8
    If A And &H10000000 Then U32ShiftLeft3 = U32ShiftLeft3 Or &H80000000
End Function

Private Function U32ShiftRight29(ByVal A As Long) As Long
    U32ShiftRight29 = (A And &HE0000000) \ &H20000000 And 7
End Function

Private Function U32RotateLeft1(ByVal A As Long) As Long
    U32RotateLeft1 = (A And &H3FFFFFFF) * 2
    If A And &H40000000 Then U32RotateLeft1 = U32RotateLeft1 Or &H80000000
    If A And &H80000000 Then U32RotateLeft1 = U32RotateLeft1 Or 1
End Function

Private Function U32RotateLeft5(ByVal A As Long) As Long
    U32RotateLeft5 = (A And &H3FFFFFF) * 32 Or (A And &HF8000000) \ &H8000000 And 31
    If A And &H4000000 Then U32RotateLeft5 = U32RotateLeft5 Or &H80000000
End Function

Private Function U32RotateLeft30(ByVal A As Long) As Long
    U32RotateLeft30 = (A And 1) * &H40000000 Or (A And &HFFFC) \ 4 And &H3FFFFFFF
    If A And 2 Then U32RotateLeft30 = U32RotateLeft30 Or &H80000000
End Function

Private Function DecToHex5(ByVal H1 As Long, ByVal H2 As Long, ByVal H3 As Long, ByVal H4 As Long, ByVal H5 As Long) As String
    Dim H As String, L As Long
    DecToHex5 = "00000000 00000000 00000000 00000000 00000000"
    H = Hex(H1): L = Len(H): Mid(DecToHex5, 9 - L, L) = H
    H = Hex(H2): L = Len(H): Mid(DecToHex5, 18 - L, L) = H
    H = Hex(H3): L = Len(H): Mid(DecToHex5, 27 - L, L) = H
    H = Hex(H4): L = Len(H): Mid(DecToHex5, 36 - L, L) = H
    H = Hex(H5): L = Len(H): Mid(DecToHex5, 45 - L, L) = H
End Function

' Convert the string into bytes so we can use the above functions
' From Chris Hulbert: http://splinter.com.au/blog

Private Function SHA1HASH(str)
    Dim i As Integer
    Dim arr() As Byte
    If (Len(str) > 0) Then
      ReDim arr(0 To Len(str) - 1) As Byte
      For i = 0 To Len(str) - 1
       arr(i) = Asc(Mid(str, i + 1, 1))
      Next i
      SHA1HASH = Replace(LCase(HexDefaultSHA1(arr)), " ", "")
    Else
      SHA1HASH = ""
    End If
End Function


Public Function GenerateSalt(Optional ByVal Length As Integer = 16) As String
    Dim i As Integer
    Dim Salt As String
    Dim RandomChar As Integer

    For i = 1 To Length
        RandomChar = Int((90 - 65 + 1) * Rnd + 65) ' Zufälliger Buchstabe A-Z
        Salt = Salt & Chr(RandomChar)
    Next i

    GenerateSalt = Salt
End Function



Sub TestEncrypt()

  Dim Encrypted As String
  Dim Decrypted As String
  Dim strPasswort As String
  strPasswort = "MyPassword"

  Encrypted = StoreEncryptAES("Mein secret Message", strPasswort)
  Debug.Print "Crypted:", Encrypted

  Decrypted = RetrieveDecryptAES(Encrypted, strPasswort)
  Debug.Print "Decrypted:", Decrypted

End Sub
