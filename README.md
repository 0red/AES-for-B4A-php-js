# AES-for-B4A-php-js


#B4A
```basic

Sub AES_Test1(text As String)
	If text="" Then text="ąśćńłóę i to było by TO"
	Dim pass As String="1234567890123456"
	Log("AES_Test1__in: " & text)
	Dim enc1 As String = AES_Encrypt(text,pass,"")
	Log("AES_Test1_sig: " & enc1)
	Dim dec1 As String = AES_Decrypt("a"&enc1,pass,"")
	Log("AES_Test1_out: " & dec1)
	
End Sub

' --------------------------Array Helpeer
Sub ArrayPartByte(arr() As Byte, f As Int, t As Int) As Byte()
	If f<0 Then f=arr.Length+f
	If f<0 Then f=0
	If f>=arr.Length Then f=arr.Length-1
	If t<0 Then t=arr.Length+t
	If t<0 Then t=0
	If t>=arr.Length Then t=arr.Length-1
	If t<f Then t=f
	
	Log("ArrayPartByte f="&f&" t="&t&" arr.le="&arr.Length)
	Dim new_array(t-f+1) As Byte
    For i = 0 To (t-f)
	'	Log(i&" "&(i+f))
        new_array(i) = arr(i+f)
    Next
    Return new_array
End Sub

Sub ArrayAppend(arr() As Object, newitem() As Object) As Object()
    Dim new_array(arr.Length+newitem.Length) As Object
    For i = 0 To arr.Length - 1
        new_array(i) = arr(i)
    Next
    For i = 0 To newitem.Length - 1
        new_array(arr.Length+i) = newitem(i)
    Next
	Return new_array
End Sub

' -------------------------- requires: Encryption Lib

Sub AES_Encrypt(input As String, pass As String, IV As String) As String

	Dim inputB() As Byte = input.GetBytes("UTF8")
	Dim passB() As Byte = pass.GetBytes("UTF8")
	Dim IVb() As Byte = IV.GetBytes("UTF8")
	If IV="" Or IV.Length<>16 Then IVb=GenerateIVByted(IV)
	Dim compress As CompressedStreams
 
	Dim kg As KeyGenerator
	Dim C As Cipher
	Dim su As StringUtils
	
 
	kg.Initialize("AES")
	kg.KeyFromBytes(passB)
 
	C.Initialize("AES/CBC/PKCS5Padding")
	C.InitialisationVector = IVb
 	Dim inputZ() As Byte =compress.CompressBytes(inputB,"zlib")
	
	Log("AES_Encrypt b:"&inputB.Length&" c:"&inputZ.Length)
	Dim datas() As Byte = C.Encrypt(inputB, kg.Key, True)
	Dim filler() As Byte=Array As Byte(Rnd(0,256),Rnd(0,256),0)
	If inputB.Length<inputZ.Length Then
		datas= C.Encrypt(inputB, kg.Key, True)
		filler=Array As Byte(Rnd(0,256),Rnd(0,256),0)
	Else
		datas= C.Encrypt(inputZ, kg.Key, True)
		filler=Array As Byte(Rnd(0,256),Rnd(0,256),1)					
	End If
 
	datas=ArrayAppendByte(filler,datas)
	datas=ArrayAppendByte(IVb,datas)
	
	Return su.EncodeBase64(datas)
End Sub

Sub AES_Decrypt(input As String, pass As String, IV As String) As String

	Dim su As StringUtils
	Dim ver() As Byte=Array As Byte(0)

	
	Dim inputB() As Byte = su.DecodeBase64(input)
	Dim passB() As Byte = pass.GetBytes("UTF8")
	Dim IVb() As Byte 
	
	If IV="" Or IV.Length<>16 Then
		IVb=ArrayPartByte(inputB,0,15)
		ver=ArrayPartByte(inputB,18,18)
		inputB=ArrayPartByte(inputB,19,-1)
	Else
		IVb = IV.GetBytes("UTF8")
	End If
 
	Dim kg As KeyGenerator
	Dim C As Cipher
 
	kg.Initialize("AES")
	kg.KeyFromBytes(passB)
	
	C.Initialize("AES/CBC/PKCS5Padding")
	'C.Initialize("AES/GCM/PKCS5Padding")
	C.InitialisationVector = IVb
	Dim datas() As Byte
	Try
		datas= C.Decrypt(inputB, kg.Key, True)
	Catch
		Log(LastException)
		Return ""
	End Try
	
	If ver(0)=1 Then
		Dim compress As CompressedStreams
 		datas=compress.DecompressBytes(datas,"zlib")	
	End If
	Return BytesToString(datas, 0, datas.Length, "UTF8")
End Sub

Sub GenerateIV (s As String) As String
	Dim PWC As String = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	Dim IV As String
	For i=0 To s.Length-1
		IV=IV & s.CharAt(i)
	Next
	
	For i=s.Length To 15
		IV=IV & PWC.CharAt(Rnd(0,PWC.Length))
	Next
	Return IV
End Sub

Sub GenerateIVByte (s As String) As Byte()
	Dim IV(16) As Byte
	For i=0 To s.Length-1
		IV(i)=Asc(s.CharAt(i))
	Next
	
	For i=s.Length To 15
		IV(i)=Rnd(0,256)
	Next
	Return IV
End Sub
```
