Imports System.Runtime.InteropServices
Imports System.Diagnostics

Public Class HandleCloserForm
    ' Windows API Declarations
    <DllImport("ntdll.dll")>
    Private Shared Function NtQuerySystemInformation(ByVal SystemInformationClass As Integer, ByVal SystemInformation As IntPtr, ByVal SystemInformationLength As Integer, ByRef ReturnLength As Integer) As Integer
    End Function

    <DllImport("kernel32.dll")>
    Private Shared Function OpenProcess(ByVal dwDesiredAccess As Integer, ByVal bInheritHandle As Boolean, ByVal dwProcessId As Integer) As IntPtr
    End Function

    <DllImport("kernel32.dll")>
    Private Shared Function DuplicateHandle(ByVal hSourceProcessHandle As IntPtr, ByVal hSourceHandle As IntPtr, ByVal hTargetProcessHandle As IntPtr, ByRef lpTargetHandle As IntPtr, ByVal dwDesiredAccess As Integer, ByVal bInheritHandle As Boolean, ByVal dwOptions As Integer) As Boolean
    End Function

    <DllImport("kernel32.dll")>
    Private Shared Function CloseHandle(ByVal hObject As IntPtr) As Boolean
    End Function

    <DllImport("kernel32.dll")>
    Private Shared Function GetCurrentProcess() As IntPtr
    End Function

    ' Constants
    Private Const PROCESS_DUP_HANDLE As Integer = &H40
    Private Const SystemHandleInformation As Integer = 16
    Private Const STATUS_SUCCESS As Integer = 0
    Private Const STATUS_INFO_LENGTH_MISMATCH As Integer = &HC0000004
    Private Const DUPLICATE_CLOSE_SOURCE As Integer = &H1

    ' Structure for handle information (adjusted for 64-bit compatibility)
    <StructLayout(LayoutKind.Sequential)>
    Private Structure SYSTEM_HANDLE_ENTRY
        Public ProcessId As UInt32
        Public ObjectTypeIndex As Byte
        Public HandleAttributes As Byte
        Public HandleValue As UShort
        Public [Object] As IntPtr
        Public GrantedAccess As UInt32
    End Structure

    ' Button click event to close handles
    Private Sub btnCloseHandles_Click(sender As Object, e As EventArgs) Handles btnCloseHandles.Click
        Dim processName As String = txtProcessName.Text.Trim()
        If String.IsNullOrEmpty(processName) Then
            lblStatus.Text = "Status: Please enter a process name."
            Return
        End If

        ' Find the process
        Dim targetProcess As Process = Nothing
        Dim processes() As Process = Process.GetProcessesByName(processName)
        If processes.Length = 0 Then
            lblStatus.Text = "Status: Process '" & processName & "' not found."
            Return
        End If

        targetProcess = processes(0)
        lblStatus.Text = "Status: Found process '" & processName & "' (PID: " & targetProcess.Id & "). Closing Mutant handles..."

        ' Open the process with appropriate access rights
        Dim processHandle As IntPtr = OpenProcess(PROCESS_DUP_HANDLE, False, targetProcess.Id)
        If processHandle = IntPtr.Zero Then
            Dim errorCode As Integer = Marshal.GetLastWin32Error()
            lblStatus.Text = "Status: Failed to open process. Error code: " & errorCode
            Return
        End If

        ' Close Mutant handles
        Try
            CloseMutantHandlesForProcess(targetProcess.Id, processHandle)
        Catch ex As Exception
            lblStatus.Text = "Status: Error closing Mutant handles: " & ex.Message
        Finally
            CloseHandle(processHandle)
        End Try
    End Sub

    ' Method to close only Mutant handles for a process
    Private Sub CloseMutantHandlesForProcess(targetProcessId As Integer, processHandle As IntPtr)
        Dim bufferSize As Integer = 1024 * 1024 ' 1MB initial buffer
        Dim buffer As IntPtr = Marshal.AllocHGlobal(bufferSize)
        Dim returnLength As Integer = 0

        ' Query system handles
        Dim status As Integer = NtQuerySystemInformation(SystemHandleInformation, buffer, bufferSize, returnLength)
        While status = STATUS_INFO_LENGTH_MISMATCH
            Marshal.FreeHGlobal(buffer)
            bufferSize = returnLength
            buffer = Marshal.AllocHGlobal(bufferSize)
            status = NtQuerySystemInformation(SystemHandleInformation, buffer, bufferSize, returnLength)
        End While

        If status <> STATUS_SUCCESS Then
            lblStatus.Text = "Status: Failed to query system handles: Status 0x" & status.ToString("X")
            Marshal.FreeHGlobal(buffer)
            Return
        End If

        ' Parse the handle information
        Dim handleCount As Integer = Marshal.ReadInt32(buffer)
        lblStatus.Text &= " | Found " & handleCount & " system handles."
        Dim offset As Integer = 8 ' Skip the first 8 bytes (NumberOfHandles on 64-bit systems)
        Dim handleSize As Integer = Marshal.SizeOf(GetType(SYSTEM_HANDLE_ENTRY))
        Dim closedHandles As Integer = 0
        Dim foundMutantHandles As Integer = 0
        Dim foundTargetHandles As Integer = 0

        ' Validate handle count to prevent buffer overrun
        Dim totalSize As Long = handleCount * CLng(handleSize)
        If totalSize > bufferSize Then
            lblStatus.Text &= " | Error: Handle count too large for buffer (" & totalSize & " > " & bufferSize & ")."
            Marshal.FreeHGlobal(buffer)
            Return
        End If

        For i As Integer = 0 To handleCount - 1
            Dim handleInfo As SYSTEM_HANDLE_ENTRY = Marshal.PtrToStructure(New IntPtr(buffer.ToInt64() + offset), GetType(SYSTEM_HANDLE_ENTRY))
            offset += handleSize

            ' Log the first few PIDs to debug
            If i < 5 Then
                lblStatus.Text &= " | Handle " & i & ": PID " & handleInfo.ProcessId
            End If

            ' Check if the handle belongs to the target process
            If handleInfo.ProcessId = targetProcessId Then
                foundTargetHandles += 1
                ' Log the type index to find the correct one for Mutant handles
                If foundTargetHandles <= 50 Then ' Log the first 50 handles for the target process
                    lblStatus.Text &= " | Target Handle " & foundTargetHandles & ": Type " & handleInfo.ObjectTypeIndex & ", Value 0x" & handleInfo.HandleValue.ToString("X")
                End If

                ' Check if the handle is a Mutant handle (type 55 on your system)
                If handleInfo.ObjectTypeIndex = 55 Then ' Updated to type 55
                    foundMutantHandles += 1

                    ' Duplicate the handle to our process so we can close it
                    Dim duplicatedHandle As IntPtr
                    Dim success As Boolean = DuplicateHandle(
                        processHandle,
                        New IntPtr(handleInfo.HandleValue),
                        GetCurrentProcess(),
                        duplicatedHandle,
                        0,
                        False,
                        DUPLICATE_CLOSE_SOURCE
                    )

                    If success Then
                        CloseHandle(duplicatedHandle)
                        closedHandles += 1
                        lblStatus.Text &= " | Closed Mutant handle 0x" & handleInfo.HandleValue.ToString("X")
                    Else
                        Dim errorCode As Integer = Marshal.GetLastWin32Error()
                        lblStatus.Text &= " | Failed to close Mutant handle 0x" & handleInfo.HandleValue.ToString("X") & " (Error: " & errorCode & ")"
                    End If
                End If
            End If
        Next

        lblStatus.Text &= " | Found " & foundTargetHandles & " handles for PID " & targetProcessId & ", found " & foundMutantHandles & " Mutant handles, closed " & closedHandles & " Mutant handles."
        Marshal.FreeHGlobal(buffer)
    End Sub

    ' Form load event to set default values
    Private Sub HandleCloserForm_Load(sender As Object, e As EventArgs) Handles MyBase.Load
        txtProcessName.Text = "CabalMain"
        lblStatus.Text = "Status: Ready"
    End Sub

    Private Sub Timer1_Tick(sender As Object, e As EventArgs) Handles Timer1.Tick
        TextBox1.Text = lblStatus.Text
    End Sub
End Class
