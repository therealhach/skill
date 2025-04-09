Public Class RAMManager_32
#Region "API"
    Private Declare Function EnumProcessModules Lib "psapi.dll" (ByVal hProcess As IntPtr, ByVal lphModule() As IntPtr, ByVal cb As Integer, ByRef lpcbNeeded As Integer) As Boolean
    Private Declare Function GetModuleBaseName Lib "psapi.dll" Alias "GetModuleBaseNameA" (ByVal hProcess As IntPtr, ByVal hModule As IntPtr, ByVal lpBaseName As System.Text.StringBuilder, ByVal nSize As Integer) As Integer
#End Region
#Region "API"
    Private Declare Function OpenProcess Lib "kernel32.dll" (ByVal dwDesiredAcess As UInt32, ByVal bInheritHandle As Boolean, ByVal dwProcessId As Int32) As IntPtr
    Private Declare Function ReadProcessMemory Lib "kernel32" (ByVal hProcess As IntPtr, ByVal lpBaseAddress As IntPtr, ByVal lpBuffer() As Byte, ByVal iSize As Integer, ByRef lpNumberOfBytesRead As Integer) As Boolean
    Private Declare Function WriteProcessMemory Lib "Kernel32" (ByVal hProcess As IntPtr, ByVal lpbaseAddress As IntPtr, ByVal lpBuffer As Byte(), ByVal nSize As UInt32, ByRef lpNumberOfBytesWritten As IntPtr) As Boolean
    Private Declare Function CloseHandle Lib "kernel32.dll" (ByVal hObject As IntPtr) As Boolean
    Private Declare Function VirtualQueryEx Lib "kernel32.dll" (ByVal hProcess As IntPtr, ByVal lpAddress As IntPtr, ByRef lpBuffer As MEMORY_BASIC_INFORMATION, ByVal dwLength As UInt32) As Int32
    Private Declare Function VirtualAllocEx Lib "kernel32.dll" (ByVal hProcess As IntPtr, ByVal lpAddress As IntPtr, ByVal dwSize As UInt32, ByVal flAllocationType As MemoryAllocationState, ByVal flProtect As MemoryAllocationProtectionType) As IntPtr
    Private Declare Function VirtualProtectEx Lib "kernel32.dll" (ByVal hProcess As IntPtr, ByVal lpAddress As IntPtr, ByVal dwSize As IntPtr, ByVal flNewProtect As UInt32, ByRef lpfoldProtect As UInt32) As Boolean
    Private Declare Function VirtualFreeEx Lib "kernel32.dll" (ByVal hProcess As IntPtr, ByVal lpAddress As IntPtr, ByVal dwSize As Int32, ByVal alloctype As MemoryAllocationState) As Boolean
    Private Declare Sub GetSystemInfo Lib "kernel32.dll" (ByRef lpSystemInfo As SYSTEM_INFO)
#End Region

#Region "Structs/Enum"
    Private Structure SYSTEM_INFO
        Dim wrocessorArchitecture As Int16
        Dim wReserved As Int16
        Dim dwPageSize As Int32
        Dim lpMinimumApplicationAddress As Int32
        Dim lpMaximumApplicationAddress As Int32
        Dim dwActiveProcessorMask As Int32
        Dim dwNumberOfProcessors As Int32
        Dim dwProcessorType As Int32
        Dim dwAllocationGranularity As Int32
        Dim wProcessorLevel As Int16
        Dim wProcessorRevision As Int16
    End Structure
    Private Structure MEMORY_BASIC_INFORMATION
        Dim BaseAddress As IntPtr
        Dim AllocationBase As IntPtr
        Dim AllocationProtect As UInt32
        Dim RegionSize As IntPtr
        Dim State As UInt32
        Dim Protect As UInt32
        Dim zType As UInt32
    End Structure
    Public Structure CPU_REGISTERS
        Dim eax As UInt32
        Dim ebx As UInt32
        Dim ecx As UInt32
        Dim edx As UInt32
        Dim edi As UInt32
        Dim esi As UInt32
        Dim ebp As UInt32
        Dim esp As UInt32
    End Structure
    Private Enum MemoryAllocationProtectionType As UInt32
        PAGE_NOACCESS = &H1
        PAGE_READONLY = &H2
        PAGE_READWRITE = &H4
        PAGE_WRITECOPY = &H8
        PAGE_EXECUTE = &H10
        PAGE_EXECUTE_READ = &H20
        PAGE_EXECUTE_READWRITE = &H40
        PAGE_EXECUTE_WRITECOPY = &H80
        PAGE_GUARD = &H100
        PAGE_NOCACHE = &H200
        PAGE_WRITECOMBINE = &H400
        PAGE_CANREAD = PAGE_READONLY Or PAGE_READWRITE Or PAGE_EXECUTE_READ Or PAGE_EXECUTE_READWRITE
        PAGE_CANEXECUTE = PAGE_EXECUTE Or PAGE_EXECUTE_READ Or PAGE_EXECUTE_READWRITE Or PAGE_WRITECOPY
        PAGE_CANWRITE = PAGE_READWRITE Or PAGE_EXECUTE_READWRITE
    End Enum
    Private Enum MemoryAllocationType As UInt32
        MEM_IMAGE = &H1000000
        MEM_MAPPED = &H40000
        MEM_PRIVATE = &H20000
    End Enum
    Private Enum MemoryAllocationState As UInt32
        Commit = &H1000
        Reserve = &H2000
        Decommit = &H4000
        Release = &H8000
        Reset = &H80000
        Physical = &H400000
        TopDown = &H100000
        WriteWatch = &H200000
        LargePages = &H20000000
    End Enum
    Private Enum OpenProcessMemoryRights As UInt32
        PROCESS_ALL_ACCESS_64bit = &H38
        PROCESS_ALL_ACCESS = &H1F0FFF '32 bit xp only?! Used exclusively.
        PROCESS_VM_OPERATION = &H8 'not used. 
        PROCESS_VM_READ = &H10 'not used. 
        PROCESS_VM_WRITE = &H20 'not used. 
    End Enum
    Public Enum CpuRegister As UInt32
        eax = 0
        ebx
        ecx
        edx
        edi
        esi
        ebp
        esp
    End Enum

#End Region

#Region "Private"
    Private _targetProcess As Process = Nothing
    Private _targetProcessHandle As IntPtr = IntPtr.Zero
    Private _systemInfo As SYSTEM_INFO
    'Private _ASM As New Fasm.ManagedFasm
    Private _mbiSize As Int32 = 0
    Public Sub New()
        ''initialize data
        _mbiSize = System.Runtime.InteropServices.Marshal.SizeOf(New MEMORY_BASIC_INFORMATION)
        GetSystemInfo(_systemInfo)
    End Sub
#End Region

#Region "Target Process"
    Public Function TryAttachToProcess(ByVal ProcName As String) As Boolean
        Dim _allProcesses() As Process = Process.GetProcesses
        For i = 0 To _allProcesses.Length - 1
            If LCase(_allProcesses(i).ProcessName) = ProcName Then
                Return TryAttachToProcess(_allProcesses(i))
            End If
        Next

        'For Each pp As Process In _allProcesses
        '    If pp.MainWindowTitle.ToLower.Contains(windowCaption.ToLower) Then
        '        'found it! proceed.
        '        Return TryAttachToProcess(pp)
        '    End If
        'Next
        Return False
    End Function
    Public Function TryAttachToProcess(ByVal proc As Process) As Boolean
        If _targetProcessHandle = IntPtr.Zero Then 'not already attached
            _targetProcess = proc
            _targetProcessHandle = OpenProcess(OpenProcessMemoryRights.PROCESS_ALL_ACCESS, False, _targetProcess.Id)
            If _targetProcessHandle = IntPtr.Zero Then
                TryAttachToProcess = False
                ' _lastErrorMessage = "OpenProcess Failed: PROCESS_ALL_ACCESS"
            Else
                'if we get here, all connected and ready to use ReadProcessMemory() & WriteProcessMemory
                TryAttachToProcess = True
            End If
        Else
            '_lastErrorMessage = "Already attached! (Please Detach first?)"
            TryAttachToProcess = False
        End If
    End Function
    Public Sub DetachFromProcess()
        If Not (_targetProcessHandle = IntPtr.Zero) Then
            _targetProcess = Nothing
            Try
                CloseHandle(_targetProcessHandle)
                _targetProcessHandle = IntPtr.Zero
                'DoOutput("MemReader::Detach() OK")
            Catch ex As Exception
                '_lastErrorMessage = "DetachFromProcess::CloseHandle ex.Message= " & ex.Message
                MessageBox.Show("MemoryManager::DetachFromProcess::CloseHandle error " & Environment.NewLine & ex.Message)
            End Try
        End If
    End Sub
    Public ReadOnly Property IsAttachedToProcess() As Boolean
        Get
            If _targetProcessHandle = IntPtr.Zero Then Return False
            If _targetProcess.HasExited Then
                'the process closed, detach gracefully.
                '_lastErrorMessage = "Target Process has been closed"
                DetachFromProcess()
                Return False
            End If
            Return True
        End Get
    End Property

    Public ReadOnly Property TargetProcess As Process
        Get
            Return _targetProcess
        End Get
    End Property
#End Region

#Region "Read*"
    Public Function ReadByte(ByVal addr As IntPtr) As Byte
        Dim _byte(0) As Byte
        ReadProcessMemory(_targetProcessHandle, addr, _byte, 1, vbNull)
        Return _byte(0)
    End Function
    Public Function ReadInt16(ByVal addr As IntPtr) As Int16
        Dim _bytes(1) As Byte
        ReadProcessMemory(_targetProcessHandle, addr, _bytes, 2, vbNull)
        Return BitConverter.ToInt16(_bytes, 0)
    End Function
    Public Function ReadInt32(ByVal addr As IntPtr) As Int32
        Dim _bytes(3) As Byte
        ReadProcessMemory(_targetProcessHandle, addr, _bytes, 4, vbNull)

        Return BitConverter.ToInt32(_bytes, 0)
    End Function
    Public Function ReadInt64(ByVal addr As IntPtr) As Int64
        Dim _bytes(7) As Byte
        ReadProcessMemory(_targetProcessHandle, addr, _bytes, 8, vbNull)
        Return BitConverter.ToInt64(_bytes, 0)
    End Function
    Public Function ReadUInt16(ByVal addr As IntPtr) As UInt16
        Dim _bytes(1) As Byte
        ReadProcessMemory(_targetProcessHandle, addr, _bytes, 2, vbNull)
        Return BitConverter.ToUInt16(_bytes, 0)
    End Function
    Public Function ReadUInt32(ByVal addr As IntPtr) As UInt32
        Dim _bytes(3) As Byte
        ReadProcessMemory(_targetProcessHandle, addr, _bytes, 4, vbNull)
        Return BitConverter.ToUInt32(_bytes, 0)
    End Function
    Public Function ReadUInt64(ByVal addr As IntPtr) As UInt64
        Dim _bytes(7) As Byte
        ReadProcessMemory(_targetProcessHandle, addr, _bytes, 8, vbNull)
        Return BitConverter.ToUInt64(_bytes, 0)
    End Function
    Public Function ReadFloat(ByVal addr As IntPtr) As Single
        Dim _bytes(3) As Byte
        ReadProcessMemory(_targetProcessHandle, addr, _bytes, 4, vbNull)
        Return BitConverter.ToSingle(_bytes, 0)
    End Function
    Public Function ReadDouble(ByVal addr As IntPtr) As Double
        Dim _bytes(7) As Byte
        ReadProcessMemory(_targetProcessHandle, addr, _bytes, 8, vbNull)
        Return BitConverter.ToDouble(_bytes, 0)
    End Function
    Public Function ReadIntPtr(ByVal addr As IntPtr) As IntPtr
        Dim _bytes(IntPtr.Size - 1) As Byte
        ReadProcessMemory(_targetProcessHandle, addr, _bytes, IntPtr.Size, Nothing)
        Try
            If IntPtr.Size = 4 Then
                Return New IntPtr(BitConverter.ToUInt32(_bytes, 0))
            Else
                Return New IntPtr(BitConverter.ToInt64(_bytes, 0))
            End If
        Catch ex As Exception
            '_lastErrorMessage = "ReadIntPtr() fail to cast IntPtr from bytes at 0x" + addr.ToString("x")
            'not sure why this happens. Usually when wow objmgr resets (ie. teleport etc)
            Return IntPtr.Zero
        End Try
    End Function
    Public Function ReadBytes(ByVal addr As IntPtr, ByVal size As Int32) As Byte()
        Dim _rtnBytes(size - 1) As Byte 'used to store bytes read from target process
        Dim _bytesRead As Int32 = 0 'counter
        If ReadProcessMemory(_targetProcessHandle, addr, _rtnBytes, size, _bytesRead) Then
            If _bytesRead <> size Then 'error checking
                MessageBox.Show("MemReader::ReadBytes() _bytesRead != size , 0x" & addr.ToString("X"))
            End If
        Else
            'ReadProcessMemory fail
            MessageBox.Show("MemReader::ReadBytes() ReadProcessMemory() FAIL , 0x" & addr.ToString("X"))
        End If
        Return _rtnBytes
    End Function
    Public Function ReadAsciiString(ByVal addr As IntPtr, Optional ByVal maxLength As Int32 = 25) As String
        ''Untested
        Dim _bytes(maxLength - 1) As Byte
        Dim _sb As New System.Text.StringBuilder
        Dim _endIndex As Int32 = 0
        Dim _ctr As Int32 = 0
        ReadProcessMemory(_targetProcessHandle, addr, _bytes, maxLength, vbNull)
        For Each bb As Byte In _bytes

            If bb = 0 Then
                _endIndex = _ctr
                Exit For
            End If
            _ctr += 1
        Next
        Return System.Text.Encoding.ASCII.GetString(_bytes, 0, _endIndex)
    End Function
    Public Function ReadUnicodeString(ByVal addr As IntPtr, Optional ByVal maxLength As Int32 = 25) As String
        ''Untested
        Dim _bytes(maxLength - 1) As Byte
        Dim _sb As New System.Text.StringBuilder
        ReadProcessMemory(_targetProcessHandle, addr, _bytes, maxLength, vbNull)
        Return System.Text.Encoding.Unicode.GetString(_bytes)
    End Function
#End Region

#Region "Write*"
    Public Function WriteInt16(ByVal addr As IntPtr, ByVal data As Int16) As Boolean
        Return WriteProcessMemory(_targetProcessHandle, addr, BitConverter.GetBytes(data), 2, vbNull)
    End Function
    Public Function WriteInt32(ByVal addr As IntPtr, ByVal data As Int32) As Boolean
        Return WriteProcessMemory(_targetProcessHandle, addr, BitConverter.GetBytes(data), 4, vbNull)
    End Function
    Public Function WriteInt64(ByVal addr As IntPtr, ByVal data As Int64) As Boolean
        Return WriteProcessMemory(_targetProcessHandle, addr, BitConverter.GetBytes(data), 8, vbNull)
    End Function
    Public Function WriteUInt16(ByVal addr As IntPtr, ByVal data As UInt16) As Boolean
        Return WriteProcessMemory(_targetProcessHandle, addr, BitConverter.GetBytes(data), 2, vbNull)
    End Function
    Public Function WriteUInt32(ByVal addr As IntPtr, ByVal data As UInt32) As Boolean
        Return WriteProcessMemory(_targetProcessHandle, addr, BitConverter.GetBytes(data), 4, vbNull)
    End Function
    Public Function WriteUInt64(ByVal addr As IntPtr, ByVal data As UInt64) As Boolean
        Return WriteProcessMemory(_targetProcessHandle, addr, BitConverter.GetBytes(data), 8, vbNull)
    End Function
    Public Function WriteFloat(ByVal addr As IntPtr, ByVal data As Single) As Boolean
        Return WriteProcessMemory(_targetProcessHandle, addr, BitConverter.GetBytes(data), 4, vbNull)
    End Function
    Public Function WriteDouble(ByVal addr As IntPtr, ByVal data As Double) As String
        Return WriteProcessMemory(_targetProcessHandle, addr, BitConverter.GetBytes(data), 8, vbNull)
    End Function
    Public Function WriteIntPtr(ByVal addr As IntPtr, ByVal ptr As IntPtr) As Boolean
        Dim _bytes(IntPtr.Size - 1) As Byte

        If IntPtr.Size = 4 Then
            _bytes = BitConverter.GetBytes(Convert.ToUInt32(ptr))
            Return WriteProcessMemory(_targetProcessHandle, addr, _bytes, 4, vbNull)
        Else
            _bytes = BitConverter.GetBytes(Convert.ToUInt64(ptr))
            Return WriteProcessMemory(_targetProcessHandle, addr, _bytes, 8, vbNull)
        End If
    End Function
    Public Function WriteUnicodeString(ByVal addr As IntPtr, ByVal str As String) As Boolean
        ''Untested
        Dim _bytes() As Byte = System.Text.Encoding.Unicode.GetBytes(str)
        Return WriteProcessMemory(_targetProcessHandle, addr, _bytes, _bytes.Length, vbNull)
    End Function
    Public Function WriteAsciiString(ByVal addr As IntPtr, ByVal str As String) As Boolean
        ''tested by xyverdevil!
        Dim _bytes() As Byte = System.Text.Encoding.ASCII.GetBytes(str)
        Return WriteProcessMemory(_targetProcessHandle, addr, _bytes, _bytes.Length, vbNull)
    End Function
    Public Function WriteBytes(ByVal addr As IntPtr, ByVal bytes() As Byte) As Boolean
        Return WriteProcessMemory(_targetProcessHandle, addr, bytes, bytes.Length, vbNull)
    End Function
#End Region

    Public Function AOBSCAN(ByVal GameName As String, ByVal ModuleName As String, ByVal Signature As Byte()) As Integer
        Dim BaseAddress, EndAddress As Int32
        For Each PM As ProcessModule In Process.GetProcessesByName(GameName)(0).Modules
            If ModuleName = PM.ModuleName Then
                BaseAddress = PM.BaseAddress
                EndAddress = BaseAddress + PM.ModuleMemorySize
            End If
        Next
        Dim curAddr As Int32 = BaseAddress
        Do
            For i As Integer = 0 To Signature.Length - 1
                If ReadByte(curAddr + i) = Signature(i) Then
                    If i = Signature.Length - 1 Then
                        MsgBox(curAddr.ToString("X"))
                        Return curAddr
                    End If
                    Continue For
                End If
                Exit For
            Next
            curAddr += 1
        Loop While curAddr < EndAddress
        Return 0
    End Function

#Region "Base Address"
#Region "Base Address Fallback"
    Public Function GetModuleBaseAddressByEnum() As IntPtr
        If _targetProcessHandle = IntPtr.Zero Then
            Return IntPtr.Zero
        End If

        Dim modules(1023) As IntPtr
        Dim cbNeeded As Integer
        If EnumProcessModules(_targetProcessHandle, modules, modules.Length * IntPtr.Size, cbNeeded) Then
            For i As Integer = 0 To (cbNeeded / IntPtr.Size) - 1
                Dim moduleName As New System.Text.StringBuilder(260)
                GetModuleBaseName(_targetProcessHandle, modules(i), moduleName, moduleName.Capacity)
                If moduleName.ToString().ToLower() = "cabalmain.exe" Then
                    Return modules(i)
                End If
            Next
        End If
        Return IntPtr.Zero
    End Function
#End Region
    Public ReadOnly Property ModuleBaseAddress As IntPtr
        Get
            If _targetProcess IsNot Nothing AndAlso Not _targetProcess.HasExited Then
                Return _targetProcess.MainModule.BaseAddress
            End If
            Return IntPtr.Zero
        End Get
    End Property
#End Region

#Region "Scan()"

    'Public Function FindPattern(ByVal hexString As String, Optional ByVal returnOnFirstOccurance As Boolean = True) As IntPtr()
    '    ''ex. format: 61 8a 22 ** ** ** ** 8b 31 ** 88 0d ** ** ** ** 8a 81
    '    Dim _hexStringChunks() As String = hexString.Split(" ")
    '    Dim _hexStringAsBytes() As Byte
    '    Dim _mask() As Byte
    '    ReDim _hexStringAsBytes(_hexStringChunks.Length - 1)
    '    ReDim _mask(_hexStringChunks.Length - 1)

    '    For xx As Int32 = 0 To _hexStringChunks.Length - 1
    '        If _hexStringChunks(xx) = "**" Then
    '            _hexStringAsBytes(xx) = &H0
    '            _mask(xx) = &H0 'unimportant char in hexString
    '        Else
    '            _hexStringAsBytes(xx) = Byte.Parse(_hexStringChunks(xx), Globalization.NumberStyles.HexNumber)
    '            _mask(xx) = &H1 'important char in hexString
    '        End If
    '    Next
    '    Dim _startTime As Date = Date.Now
    '    'DoOutput("FindPattern()")
    '    Dim _results() As IntPtr = ScanForBytes(_hexStringAsBytes, _mask, returnOnFirstOccurance) 'magic here
    '    Dim _timeLapse As TimeSpan = Date.Now.Subtract(_startTime)
    '    'DoOutput("Total time: " & _timeLapse.TotalSeconds & "s")
    '    Return _results
    'End Function
    'Public Function ScanForBytes(ByVal buff() As Byte, Optional ByVal returnOnFirstOccurance As Boolean = False) As IntPtr()
    '    Dim _mask(buff.Length - 1) As Byte
    '    For xx As Int32 = 0 To buff.Length - 1
    '        _mask(xx) = &H1
    '    Next
    '    Return ScanForBytes(buff, _mask, returnOnFirstOccurance)
    'End Function
    '    Public Function ScanForBytes(ByVal buff() As Byte, ByVal mask() As Byte, Optional ByVal returnOnFirstOccurance As Boolean = False) As IntPtr()
    '        ''Returns 1 intptr if bytes not found. so resultArray.Length is always atleast 1
    '        ''returned intptr = intptr.zero
    '        Dim _rtns As New List(Of IntPtr)
    '        If (mask.Length <> buff.Length) Or IsAttachedToProcess() = False Then
    '            _rtns.Add(IntPtr.Zero)
    '            Return _rtns.ToArray
    '        End If
    '        _rtns.Capacity = 1000
    '        Dim _mbi As MEMORY_BASIC_INFORMATION, _sysInfo As SYSTEM_INFO
    '        Dim _mbiSize As Int32 = System.Runtime.InteropServices.Marshal.SizeOf(_mbi)
    '        GetSystemInfo(_sysInfo)
    '        Dim _addr As IntPtr = IntPtr.Zero
    '        Dim _readBuff(_sysInfo.dwPageSize - 1) As Byte
    '        Dim _bigBuff(0) As Byte
    '        Dim _actualBytesRead As Int32 = 0 ''actual length of bytes copied during ReadProcessMemory()
    '        Dim _origPageProtection As UInt32 = 0 ''To restore old VirtualProtectEx() values after ReadProcessMemory
    '        Dim _foundIt As Boolean = False
    '        'DoOutput("ScanForBytes()")
    '        Do
    '            VirtualQueryEx(_targetProcessHandle, _addr, _mbi, _mbiSize)
    '            If _mbi.State = MemoryAllocationState.Commit Then
    '                'this region of ram actively being used by process (commited at least..)
    '                If Not ((_mbi.Protect And MemoryAllocationProtectionType.PAGE_CANREAD) And Not (_mbi.Protect And MemoryAllocationProtectionType.PAGE_GUARD)) Then 'bitmask (checks for any readable type)
    '                    'VirtualProtectEx() required to enable read access
    '                    If _mbi.Protect And MemoryAllocationProtectionType.PAGE_CANEXECUTE Then
    '                        'it should remain executable! 
    '                        If VirtualProtectEx(_targetProcessHandle, _mbi.BaseAddress, _mbi.RegionSize, MemoryAllocationProtectionType.PAGE_EXECUTE_READWRITE, _origPageProtection) Then
    '                            'DoOutput("execPatching 0x" & _addr.ToString("X"))
    '                        Else
    '                            'DoOutput("execPatching 0x" & _addr.ToString("X") & " FAIL?")
    '                        End If
    '                    Else
    '                        If VirtualProtectEx(_targetProcessHandle, _mbi.BaseAddress, _mbi.RegionSize, MemoryAllocationProtectionType.PAGE_READWRITE, _origPageProtection) Then
    '                            'DoOutput("readPatching 0x" & _mbi.BaseAddress.ToString("X"))
    '                        Else
    '                            'DoOutput("readPatching 0x" & _mbi.BaseAddress.ToString("X") & " FAIL?")
    '                        End If
    '                    End If
    '                End If
    '                ''Read the data.
    '                If _mbi.RegionSize.ToInt32 <= _sysInfo.dwPageSize Then
    '                    'small page. Read entire page into buffer.
    '                    If ReadProcessMemory(_targetProcessHandle, _mbi.BaseAddress, _readBuff, _mbi.RegionSize, _actualBytesRead) Then
    '                        If (_actualBytesRead <> _mbi.RegionSize) Or _readBuff.Length <> _mbi.RegionSize Then
    '                            'not able to read all data, handle gracefully. do nothing :)
    '                            'DoOutput("ScanForBytes() RPM->ActualBytesRead too low! 0x" & _mbi.BaseAddress.ToString("X"))
    '                        Else
    '                            For xx As Int32 = 0 To _mbi.RegionSize.ToInt32 - buff.Length
    '                                For yy As Int32 = 0 To buff.Length - 1
    '                                    If mask(yy) <> 0 Then
    '                                        If buff(yy) <> _readBuff(xx + yy) Then
    '                                            GoTo badLabelNoSuccess
    '                                        End If
    '                                    End If
    '                                Next
    '                                _rtns.Add(_addr.ToInt32 + xx)  'found it
    '                                _foundIt = True
    'badLabelNoSuccess:
    '                            Next
    '                        End If
    '                    Else
    '                        'DoOutput("ScanForBytes::RPM FAIL 0x" & _mbi.BaseAddress.ToString("X"))
    '                    End If
    '                Else
    '                    'large page. Read page in chunks.
    '                    _bigBuff = ReadLargeRamPage(_addr, _addr.ToInt32 + _mbi.RegionSize.ToInt32)
    '                    For xx As Int32 = 0 To _bigBuff.Length - buff.Length
    '                        For yy As Int32 = 0 To buff.Length - 1
    '                            If mask(yy) <> 0 Then
    '                                If buff(yy) <> _bigBuff(xx + yy) Then
    '                                    GoTo badLabelNoMoreSuccess
    '                                End If
    '                            End If
    '                        Next
    '                        _rtns.Add(_addr.ToInt32 + xx) 'found it
    '                        _foundIt = True
    'badLabelNoMoreSuccess:
    '                    Next

    '                End If ''//page size
    '                '' Restore original page protection?
    '                If _origPageProtection Then
    '                    'DoOutput("unPatching->0x" & _addr.ToString("X"))
    '                    VirtualProtectEx(_targetProcessHandle, _mbi.BaseAddress, _mbi.RegionSize, _origPageProtection, _origPageProtection)
    '                    _origPageProtection = 0
    '                End If
    '                If returnOnFirstOccurance And _foundIt Then
    '                    Exit Do
    '                End If
    '            End If ''//state=committed
    '            _addr = _mbi.BaseAddress.ToInt32 + _mbi.RegionSize.ToInt32 ''increment _addr to next region
    '        Loop While _addr.ToInt32 < &H7FFE0000 '_sysInfo.lpMaximumApplicationAddress

    '        If _rtns.Count > 0 Then
    '            'DoOutput("Found at..")
    '            For Each ppp As IntPtr In _rtns
    '                'DoOutput("0x" & ppp.ToString("X"))
    '            Next
    '        Else
    '            'DoOutput("Not Found")
    '            _rtns.Add(IntPtr.Zero)
    '        End If
    '        Return _rtns.ToArray
    '    End Function
    'Private Function ReadLargeRamPage(ByVal aStart As IntPtr, ByVal aStop As IntPtr) As Byte()
    '    Dim _rtnBuffSize As Int32 = aStop.ToInt32 - aStart.ToInt32 'theoretical max size: may be smaller due to Read fails
    '    Dim _sizeRemaining As Int32 = _rtnBuffSize
    '    Dim _byteBuff() As Byte
    '    ReDim _byteBuff(_rtnBuffSize - 1)
    '    Dim _byteBuffCurrIndex As Int32 = 0 'actual size of data to be returned
    '    Dim _curAddr As IntPtr = aStart
    '    Dim _readBuff(_systemInfo.dwPageSize) As Byte
    '    Dim _actualBytesRead As Int32 = 0 '' Actual count of bytes read by ReadProcessMemory()
    '    'start reading
    '    Do

    '        If _sizeRemaining >= _systemInfo.dwPageSize Then
    '            If ReadProcessMemory(_targetProcessHandle, _curAddr, _readBuff, _systemInfo.dwPageSize, _actualBytesRead) Then
    '                If (_actualBytesRead <> _systemInfo.dwPageSize) Then
    '                    'didn't read all data?! Don't append _readBuff to byteBuff
    '                    'DoOutput("ReadLargeRamChunk() RPM->ActualBytesRead too low! 0x" & _curAddr.ToString("X"))
    '                Else
    '                    Array.Copy(_readBuff, 0, _byteBuff, _byteBuffCurrIndex, _systemInfo.dwPageSize)
    '                    _byteBuffCurrIndex += _systemInfo.dwPageSize
    '                End If
    '            Else
    '                'DoOutput("ReadLargeRamChunk() RPM->FAIL! 0x" & _curAddr.ToString("X"))
    '                Application.DoEvents()
    '                'Beep()
    '                Threading.Thread.Sleep(2000)
    '            End If
    '            _curAddr = _curAddr.ToInt32 + _systemInfo.dwPageSize
    '            _sizeRemaining -= _systemInfo.dwPageSize
    '            If _sizeRemaining = 0 Then Exit Do
    '        Else
    '            'almost at end of mem scan. 1 small piece left
    '            If ReadProcessMemory(_targetProcessHandle, _curAddr, _readBuff, _sizeRemaining, _actualBytesRead) Then
    '                If (_actualBytesRead <> _sizeRemaining) Or (_readBuff.Length <> _sizeRemaining) Then
    '                    'not able to read entire area
    '                    DoOutput("ReadLargeRamChunk() RPM->ActualBytesRead too low! (final chunk)")
    '                Else
    '                    Array.Copy(_readBuff, 0, _byteBuff, _byteBuffCurrIndex, _sizeRemaining)
    '                    'success
    '                    Exit Do
    '                End If

    '            Else
    '                'DoOutput("ReadLargeRamChunk() RPM->FAIL! (final chunk)")
    '                Application.DoEvents()
    '                Beep()
    '                Threading.Thread.Sleep(2000)
    '            End If
    '        End If
    '    Loop
    '    If _byteBuffCurrIndex < _rtnBuffSize Then
    '        'not all data read. _byteBuff is too large. Shrink it.
    '        ReDim Preserve _byteBuff(_byteBuffCurrIndex + 1) ''sloppy and inefficient? rarely happens.?
    '    End If

    '    Return _byteBuff
    'End Function

#End Region

    '#Region "h4ck"
    '    Private Function VirtualQueryEx(ByVal addr As IntPtr, ByRef mbi As MEMORY_BASIC_INFORMATION) As Boolean 'syntax sugar
    '        Return VirtualQueryEx(_targetProcessHandle, addr, mbi, _mbiSize)
    '    End Function
    '    Private Function Malloc(ByVal sizw As Int32, Optional ByVal dwAddress As Int64 = 0) As IntPtr 'syntax sugar
    '        Return VirtualAllocEx(_targetProcessHandle, dwAddress, sizw, MemoryAllocationState.Commit, MemoryAllocationProtectionType.PAGE_EXECUTE_READWRITE)
    '    End Function
    '    Private Sub Falloc(ByVal _addr As IntPtr)
    '        Dim _mbi As MEMORY_BASIC_INFORMATION
    '        VirtualQueryEx(_addr, _mbi)
    '        VirtualFreeEx(_targetProcessHandle, _mbi.BaseAddress, _mbi.RegionSize, MemoryAllocationState.Decommit)
    '        ''Is _mbi.RegionSize necessary?
    '        ''or will VirtualFreeEx() take a size of 1 and auto figure out to decomit the entire region??
    '    End Sub
    '    Private Function GetByteCode(ByVal _asms() As String) As Byte()
    '        _ASM.Clear() '' as Managed.Fasm . see comment below.
    '        For Each ss As String In _asms
    '            _ASM.AddLine(ss)
    '        Next
    '        Return _ASM.Assemble '<-- credits to managed_fasm.dll found at http://www.ownedcore.com
    '    End Function
    '    Public Function GetRegisterOnce(ByVal sourceLoc As IntPtr, ByVal register As CpuRegister, ByVal maxWaitTimeInSeconds As Int32) As IntPtr
    '        Dim _codeCaveStartLoc As IntPtr = Malloc(200) 'in wow.exe ram, used to store (then run) bytecode. todo: auto-sized
    '        Dim _codeCaveCode(0) As Byte ' stores bytecode to inject into process
    '        Dim _origAsmLoc As IntPtr = _codeCaveStartLoc.ToInt32 + 100 'executable's orig. code copied here (8 bytes)
    '        Dim _rtnValueLoc As IntPtr = _codeCaveStartLoc.ToInt32 + 175 'where our asm code copies the register to
    '        Dim _origProcessByteCode() As Byte = ReadBytes(sourceLoc, 8) 'orig. wow.exe code (must be restored by codecave code)
    '        WriteBytes(_origAsmLoc, _origProcessByteCode)
    '        'Create codeCave byte code (copy,cleanup,return)
    '        'copy register to our dump location
    '        Dim registerAsString As String = System.Enum.GetName(GetType(CpuRegister), register) 'awk
    '        Dim sb As New System.Text.StringBuilder
    '        With sb
    '            'save registers (that I use) to avoid corrupting stack
    '            .AppendLine("push eax")
    '            .AppendLine("push ebx")
    '            .AppendLine("push edx")
    '            'copy our rtnValueLoc to a register
    '            .AppendLine("mov eax, " & _rtnValueLoc.ToInt32.ToString)
    '            'copy register into the [value] at rtnValueLoc
    '            .AppendLine("mov [eax], " & registerAsString) 'the magic happens right here
    '            'clean-up
    '            .AppendLine("mov eax, " & sourceLoc.ToInt32.ToString)
    '            .AppendLine("mov ebx, " & _origAsmLoc.ToInt32.ToString)
    '            .AppendLine("mov edx, [ebx]") 'copy 4 bytes from _origAsmLoc to exe source_loc
    '            .AppendLine("mov [eax], edx") ' ie. unpatch using exe's orig source code
    '            .AppendLine("add ebx, 4")
    '            .AppendLine("add eax, 4")
    '            .AppendLine("mov edx, [ebx]") 'copy next/last 4 bytes back into wow.exe
    '            .AppendLine("mov [eax], edx") '
    '            .AppendLine("pop edx") 'pop order is important. duh.
    '            .AppendLine("pop ebx")
    '            .AppendLine("pop eax")

    '        End With
    '        Dim _individualAsmStrings() As String = Split(sb.ToString, Environment.NewLine)
    '        If _individualAsmStrings(_individualAsmStrings.Length - 1) = "" Then ReDim Preserve _individualAsmStrings(_individualAsmStrings.Length - 2) 'chop off empty string: last call should use ASM.Append() Not AppendLine() ? works.
    '        Dim _cdc() As Byte 'codecave bytecode, except 5 bytes for a JMP command.
    '        _cdc = GetByteCode(_individualAsmStrings)
    '        Dim _jmpAsm(4) As Byte ' hand crafted JMP command : instead of using managed_fasm.assemble("JMP address")..Educational.
    '        _jmpAsm(0) = &HE9 'opcode for Relative jump
    '        ReDim _codeCaveCode(_cdc.Length - 1 + 5) '5 = _jmpAsm.Length in bytes, 'E9' + 4 byte ram address

    '        Dim _bts() As Byte = BitConverter.GetBytes(sourceLoc.ToInt32 - _codeCaveStartLoc.ToInt32 - _codeCaveCode.Length) 'address where codecave jmps back to. (ie. sourceLoc, but relative* because I use 'E9' for JMP not 'FF') !!!
    '        _bts.Reverse() 'endianness of bytecode
    '        Array.Copy(_bts, 0, _jmpAsm, 1, 4) 'copy the 4 byte address into the asm jmp command
    '        Array.Copy(_cdc, _codeCaveCode, _cdc.Length) 'copy the codecavecode(w/o jmp) to array
    '        Array.Copy(_jmpAsm, 0, _codeCaveCode, _codeCaveCode.Length - 5, 5) 'copy jmp command to end of array

    '        WriteBytes(_codeCaveStartLoc, _codeCaveCode) 'write the bytecode (100% complete now) into process's ram.
    '        ''Write Jmp command to sourceLoc. ie. WILL make it re-route
    '        _bts = BitConverter.GetBytes(_codeCaveStartLoc.ToInt32 - (sourceLoc.ToInt32 + 5)) 'address of beginning of codecave. +5 because in asm, JMP is relative* to the NEXT instruction. Jmp is 5 bytes long.
    '        _bts.Reverse() 'indianness of byte code
    '        Array.Copy(_bts, 0, _jmpAsm, 1, 4) '_jmpAsm is now complete, again.
    '        Dim scanStartTime As DateTime = Date.Now
    '        Dim scanTimeLapse As TimeSpan
    '        'enable ram to be written to
    '        Dim _origAccessRights As UInt32 = 0
    '        Dim _mbi As MEMORY_BASIC_INFORMATION
    '        VirtualQueryEx(_targetProcessHandle, sourceLoc, _mbi, _mbiSize)
    '        If Not (_mbi.Protect And MemoryAllocationProtectionType.PAGE_EXECUTE_READWRITE) Then
    '            'change rights
    '            If Not VirtualProtectEx(_targetProcessHandle, _mbi.BaseAddress, _mbi.RegionSize, MemoryAllocationProtectionType.PAGE_EXECUTE_READWRITE, _origAccessRights) Then
    '                modPublic.DoOutput("MemManager::CopyRegister::VirtualProtectEx() fail 0x" & sourceLoc.ToString("X"))
    '                modPublic.DoOutput("You should probably stop..unexpected results guaranteed")
    '                Return IntPtr.Zero 'can't write to this memory?
    '            End If
    '        End If
    '        'if we get here, orig perms. were exec_r_w or VirtualProtect succeeded
    '        WriteBytes(sourceLoc, _jmpAsm) ' .Patch()
    '        'DoOutput("scanning for rtn value...")
    '        Dim _origJumpLocCode As UInt64 = BitConverter.ToUInt64(_origProcessByteCode, 0) 'because orig asm is only 8 bytes i used int64. should use byte array.
    '        Do Until ReadUInt64(sourceLoc) = _origJumpLocCode 'do until the codecave unpatches itsself!(ie. orig code has been restored) nifty.
    '            scanTimeLapse = Date.Now.Subtract(scanStartTime)
    '            If scanTimeLapse.TotalSeconds > maxWaitTimeInSeconds Then
    '                'we need to manually put the source Bcode back. cuz wow might actually use it later :/
    '                WriteBytes(sourceLoc, _origProcessByteCode)
    '                If _origAccessRights Then
    '                    'we changed rights, change them back.
    '                    VirtualProtectEx(_targetProcessHandle, _mbi.BaseAddress, _mbi.RegionSize, _origAccessRights, New UInt32)
    '                End If
    '                'modPublic.DoOutput("MemManager::GetRegister() Time limit exceeded: " & maxWaitTimeInSeconds.ToString & "s")
    '                Return IntPtr.Zero ' wow.exe code never got called. or other asm/codecavecode error?...
    '            End If
    '        Loop
    '        'if we get here, success!
    '        Dim _rtnPtr As IntPtr = ReadIntPtr(_rtnValueLoc) ' == register value !
    '        'modPublic.DoOutput("success: val=" & _rtnPtr.ToString("x"))
    '        'free mem allocated for codecave inside wow
    '        VirtualFreeEx(_targetProcessHandle, _codeCaveStartLoc, 200, MemoryAllocationState.Decommit)
    '        'restore access rights?
    '        If _origAccessRights <> 0 Then
    '            VirtualProtectEx(_targetProcessHandle, _mbi.BaseAddress, _mbi.RegionSize, _origAccessRights, New Int32)
    '        End If
    '        Return _rtnPtr
    '    End Function
    '    Private Function GetRegistersAllOnce(ByVal sourceLoc As IntPtr, ByVal maxWaitTimeInSeconds As Int32) As CPU_REGISTERS
    '        Dim _rtnRegisters As CPU_REGISTERS
    '        Dim _codeCaveStartLoc As IntPtr = Malloc(200)
    '        Dim _codeCaveCode() As Byte ' stores bytecode to inject into process
    '        Dim _origAsmLoc As IntPtr = _codeCaveStartLoc.ToInt32 + 190 'code-cave's orig. code copied here (8 bytes)
    '        Dim _rtnValueLoc As IntPtr = _codeCaveStartLoc.ToInt32 + 100 'where our asm code copies the register
    '        Dim _origProcessByteCode() As Byte = ReadBytes(sourceLoc, 8) 'original process asm, which we replace w/ JMP 
    '        WriteBytes(_origAsmLoc, _origProcessByteCode)
    '        'copy the register to our dump location
    '        Dim sb As New System.Text.StringBuilder
    '        With sb
    '            .AppendLine("push eax")
    '            .AppendLine("push edx")
    '            .AppendLine("mov edx, " & _rtnValueLoc.ToInt32.ToString) 'start of rtn value loc in memory
    '            'copy registers into rtnValueLoc demp are
    '            .AppendLine("mov [edx], eax") 'copy eax
    '            .AppendLine("add edx, 4")
    '            .AppendLine("mov [edx], ebx") 'copy ebx
    '            .AppendLine("add edx, 4")
    '            .AppendLine("mov [edx], ecx") 'copy ecx
    '            .AppendLine("add edx, 4")
    '            .AppendLine("mov eax, edx")   'switch register being used as the counter
    '            .AppendLine("pop edx")
    '            .AppendLine("mov [eax], edx") 'copy edx
    '            .AppendLine("add eax, 4")
    '            .AppendLine("mov [eax], edi") 'copy esi
    '            .AppendLine("add eax, 4")
    '            .AppendLine("mov [eax], esi") 'copy edi
    '            .AppendLine("add eax, 4")
    '            .AppendLine("mov [eax], ebp") 'copy ebp
    '            .AppendLine("add eax, 4")
    '            .AppendLine("mov [eax], esp") 'copy esp
    '            'clean-up
    '            .AppendLine("push ebx")
    '            .AppendLine("push edx")
    '            .AppendLine("mov eax, " & sourceLoc.ToInt32.ToString)
    '            .AppendLine("mov ebx, " & _origAsmLoc.ToInt32.ToString)
    '            .AppendLine("mov edx, [ebx]")
    '            .AppendLine("mov [eax], edx")
    '            .AppendLine("add ebx, 4")
    '            .AppendLine("add eax, 4")
    '            .AppendLine("mov edx, [ebx]")
    '            .AppendLine("mov [eax], edx")
    '            .AppendLine("pop edx")
    '            .AppendLine("pop ebx")
    '            .AppendLine("pop eax")
    '        End With
    '        Dim _individualAsmStrings() As String = Split(sb.ToString, Environment.NewLine)
    '        Dim _cdc() As Byte 'codecave bytecode, minus 5 bytes for the JMP command.
    '        Dim _jmpAsm(4) As Byte ' hand crafted JMP command : instead of using managed_fasm.assemble("JMP offset")..
    '        _jmpAsm(0) = &HE9 'opcode for relative jump
    '        If _individualAsmStrings(_individualAsmStrings.Length - 1) = "" Then ReDim Preserve _individualAsmStrings(_individualAsmStrings.Length - 2) 'chop off empty string at end..
    '        _cdc = GetByteCode(_individualAsmStrings)
    '        ReDim _codeCaveCode(_cdc.Length - 1 + 5) '5 = _jmpAsm.Length in bytes, 'E9' + 4 bytes. -1 for explicitness

    '        Dim _bts() As Byte = BitConverter.GetBytes(sourceLoc.ToInt32 - _codeCaveStartLoc.ToInt32 - _codeCaveCode.Length) 'address where codecave jmps back to. (ie. sourceLoc, but relative because I use 'E9' for JMP not 'FF')
    '        _bts.Reverse() ' endianness
    '        Array.Copy(_bts, 0, _jmpAsm, 1, 4) 'copy the 4 byte address into the asm command
    '        Array.Copy(_cdc, _codeCaveCode, _cdc.Length) 'copy the codecavecode(w/o jmp) to Array()
    '        Array.Copy(_jmpAsm, 0, _codeCaveCode, _codeCaveCode.Length - 5, 5) 'copy asm command to end of Array()

    '        WriteBytes(_codeCaveStartLoc, _codeCaveCode) 'write the bytecode (100% complete now) into process's ram.
    '        ''Write Jmp command to sourceLoc 
    '        _bts = BitConverter.GetBytes(_codeCaveStartLoc.ToInt32 - (sourceLoc.ToInt32 + 5)) 'address of beginning of codecave. +5 because in asm, JMP is relative to the NEXT instruction. Jmp is 5 bytes long.
    '        _bts.Reverse() 'indian
    '        Array.Copy(_bts, 0, _jmpAsm, 1, 4)

    '        Dim scanStartTime As DateTime = Date.Now
    '        Dim scanTimeLapse As TimeSpan
    '        'enable ram to be written to
    '        Dim _origAccessRights As UInt32 = 0
    '        Dim _mbi As MEMORY_BASIC_INFORMATION
    '        VirtualQueryEx(_targetProcessHandle, sourceLoc, _mbi, _mbiSize)
    '        If Not (_mbi.Protect And MemoryAllocationProtectionType.PAGE_EXECUTE_READWRITE) Then
    '            'change rights
    '            If Not VirtualProtectEx(_targetProcessHandle, _mbi.BaseAddress, _mbi.RegionSize, MemoryAllocationProtectionType.PAGE_EXECUTE_READWRITE, _origAccessRights) Then
    '                modPublic.DoOutput("CodeCave::CopyRegisterOnce::VirtualProtectEx fail 0x" & sourceLoc.ToString("X"))
    '                Return New CPU_REGISTERS 'can't write to this memory?
    '            End If
    '        End If
    '        'if we get here, orig perms. were exec_r_w or VirtualProtect worked
    '        WriteBytes(sourceLoc, _jmpAsm) 'Patch. Write JMP command to process code --next time it's ran, our codecave gets executed!
    '        'modPublic.DoOutput("scanning for rtn value...")
    '        Dim _origJumpLocCode As UInt64 = BitConverter.ToUInt64(_origProcessByteCode, 0)

    '        Do Until ReadUInt64(sourceLoc) = _origJumpLocCode
    '            scanTimeLapse = Date.Now.Subtract(scanStartTime)
    '            If scanTimeLapse.TotalSeconds > maxWaitTimeInSeconds Then
    '                'we need to manually put the source Bcode back. cuz wow might actually use it later :/
    '                WriteBytes(sourceLoc, _origProcessByteCode)
    '                If _origAccessRights Then
    '                    'we changed rights, change them back.
    '                    VirtualProtectEx(_targetProcessHandle, _mbi.BaseAddress, _mbi.RegionSize, _origAccessRights, New UInt32)
    '                End If
    '                modPublic.DoOutput("MemManager::GetRegistersAll() Time limit exceeded: " & maxWaitTimeInSeconds.ToString & "s")
    '                Return New CPU_REGISTERS
    '            End If
    '        Loop
    '        'if we get here, success!
    '        Dim _rtnBytes() As Byte = ReadBytes(_rtnValueLoc, 32)
    '        _rtnRegisters.eax = BitConverter.ToUInt32(_rtnBytes, 0) '' sloppy?
    '        _rtnRegisters.ebx = BitConverter.ToUInt32(_rtnBytes, 4)
    '        _rtnRegisters.ecx = BitConverter.ToUInt32(_rtnBytes, 8)
    '        _rtnRegisters.edx = BitConverter.ToUInt32(_rtnBytes, 12)
    '        _rtnRegisters.edi = BitConverter.ToUInt32(_rtnBytes, 16)
    '        _rtnRegisters.esi = BitConverter.ToUInt32(_rtnBytes, 20)
    '        _rtnRegisters.ebp = BitConverter.ToUInt32(_rtnBytes, 24)
    '        _rtnRegisters.esp = BitConverter.ToUInt32(_rtnBytes, 28)
    '        'free VirtualAllocEx memory
    '        VirtualFreeEx(_targetProcessHandle, _codeCaveStartLoc, 200, MemoryAllocationState.Decommit)
    '        'restore rights?
    '        If _origAccessRights Then
    '            VirtualProtectEx(_targetProcessHandle, _mbi.BaseAddress, _mbi.RegionSize, _origAccessRights, New Int32)
    '        End If
    '        Return _rtnRegisters
    '    End Function

    '#End Region

End Class
