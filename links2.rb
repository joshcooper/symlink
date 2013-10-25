require 'fileutils'
require 'ffi'
require 'pry'

module Windows
  module API
    extend FFI::Library
    ffi_lib 'kernel32'
    ffi_convention :stdcall

    # BOOLEAN WINAPI CreateSymbolicLink(
    #   _In_  LPTSTR lpSymlinkFileName, - symbolic link to be created
    #   _In_  LPTSTR lpTargetFileName, - name of target for symbolic link
    #   _In_  DWORD dwFlags - 0x0 target is a file, 0x1 target is a directory
    # );
    attach_function :create_symbolic_link, :CreateSymbolicLinkW,
      [:pointer, :pointer, :uint], :uint

    # DWORD WINAPI GetFileAttributes(
    #   _In_  LPCTSTR lpFileName
    # );
    attach_function :get_file_attributes, :GetFileAttributesW, [:pointer], :uint

    # HANDLE WINAPI CreateFile(
    #   _In_      LPCTSTR lpFileName,
    #   _In_      DWORD dwDesiredAccess,
    #   _In_      DWORD dwShareMode,
    #   _In_opt_  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    #   _In_      DWORD dwCreationDisposition,
    #   _In_      DWORD dwFlagsAndAttributes,
    #   _In_opt_  HANDLE hTemplateFile
    # );
    attach_function :create_file, :CreateFileW,
      [:pointer, :uint, :uint, :pointer, :uint, :uint, :uint], :uint

    # http://msdn.microsoft.com/en-us/library/windows/desktop/aa363216(v=vs.85).aspx
    # BOOL WINAPI DeviceIoControl(
    #   _In_         HANDLE hDevice,
    #   _In_         DWORD dwIoControlCode,
    #   _In_opt_     LPVOID lpInBuffer,
    #   _In_         DWORD nInBufferSize,
    #   _Out_opt_    LPVOID lpOutBuffer,
    #   _In_         DWORD nOutBufferSize,
    #   _Out_opt_    LPDWORD lpBytesReturned,
    #   _Inout_opt_  LPOVERLAPPED lpOverlapped
    # );
    attach_function :device_io_control, :DeviceIoControl,
      [:uint, :uint, :pointer, :uint, :pointer, :uint, :pointer, :pointer], :bool

    MAXIMUM_REPARSE_DATA_BUFFER_SIZE = 16384

    # REPARSE_DATA_BUFFER
    # http://msdn.microsoft.com/en-us/library/cc232006.aspx
    # http://msdn.microsoft.com/en-us/library/windows/hardware/ff552012(v=vs.85).aspx
    # struct is always MAXIMUM_REPARSE_DATA_BUFFER_SIZE bytes
    class ReparseDataBuffer < FFI::Struct
      layout :reparse_tag, :uint,
             :reparse_data_length, :ushort,
             :reserved, :ushort,
             :substitute_name_offset, :ushort,
             :substitute_name_length, :ushort,
             :print_name_offset, :ushort,
             :print_name_length, :ushort,
             # max less above fields dword / uint 4 bytes, ushort 2 bytes
             :path_buffer, [:uint16, (MAXIMUM_REPARSE_DATA_BUFFER_SIZE - 16) / 2]
    end

    # BOOL WINAPI CloseHandle(
    #   _In_  HANDLE hObject
    # );
    attach_function :close_handle, :CloseHandle, [:uint], :bool
  end

  def self.to_wide_str(str)
    str.encoding.to_s == 'UTF-16LE' ? str : "#{str}\0".encode('UTF-16LE')
  end

  def self.create_symbolic_link(symlink, target)
    flags = File.directory?(target) ? 0x1 : 0x0
    result = API.create_symbolic_link(to_wide_str(symlink), to_wide_str(target), flags)
    return true unless result == 0
    raise new("CreateSymbolicLink(#{symlink}, #{target}, #{flags.to_s(8)})")
  end

  INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
  def self.get_file_attributes(file_name)
    result = API.get_file_attributes(to_wide_str(file_name))
    return result unless result == INVALID_FILE_ATTRIBUTES
    raise new("GetFileAttributes(#{file_name})")
  end

  INVALID_HANDLE_VALUE = -1
  def self.create_file(file_name, desired_access, share_mode, security_attributes,
    creation_disposition, flags_and_attributes, template_file_handle)

    result = API.create_file(to_wide_str(file_name), desired_access,
      share_mode, security_attributes, creation_disposition,
      flags_and_attributes, template_file_handle)

    return result unless result == INVALID_HANDLE_VALUE
    raise new("CreateFile(#{file_name}, #{desired_access.to_s(8)}, #{share_mode.to_s(8)}, " +
        "#{security_attributes}, #{creation_disposition.to_s(8)}, " +
        "#{flags_and_attributes.to_s(8)}, #{template_file_handle})")
  end

  def self.device_io_control(handle, io_control_code, in_buffer = nil, out_buffer = nil)
    if out_buffer.nil?
      raise new("out_buffer is required")
    end

    result = API.device_io_control(
      handle,
      io_control_code,
      in_buffer, in_buffer.nil? ? 0 : in_buffer.size,
      out_buffer, out_buffer.size,
      FFI::MemoryPointer.new(:uint, 1),
      nil
    )

    return out_buffer unless result == 0
    raise new("DeviceIoControl(#{handle}, #{io_control_code}, #{in_buffer}, #{in_buffer.size}, #{out_buffer}, #{out_buffer.size}")
  end

  FILE_ATTRIBUTE_REPARSE_POINT = 0x400
  def self.symlink?(file_name)
    attributes = get_file_attributes(file_name)
    attributes & FILE_ATTRIBUTE_REPARSE_POINT == FILE_ATTRIBUTE_REPARSE_POINT
  end

  GENERIC_READ                  = 0x80000000
  FILE_SHARE_READ               = 1
  OPEN_EXISTING                 = 3
  FILE_FLAG_OPEN_REPARSE_POINT  = 0x00200000
  FILE_FLAG_BACKUP_SEMANTICS    = 0x02000000

  # TODO: this should be marked private
  def self.open_symlink(link_name)
    create_file(
      to_wide_str(link_name),
      GENERIC_READ,
      FILE_SHARE_READ,
      nil, # security_attributes
      OPEN_EXISTING,
      FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
      0) # template_file
  end

  # http://msdn.microsoft.com/en-us/library/windows/desktop/aa364571(v=vs.85).aspx
  FSCTL_GET_REPARSE_POINT = 0x900a8

  # TODO: this should be marked private
  def self.resolve_symlink(handle)

    # must be multiple of 1024, min 10240
    out_buffer = FFI::MemoryPointer.new(API::ReparseDataBuffer.size)
    device_io_control(handle, FSCTL_GET_REPARSE_POINT, nil, out_buffer)

    reparse_data = API::ReparseDataBuffer.new(out_buffer)
    offset = reparse_data[:print_name_offset] / 2 + 2
    length = reparse_data[:print_name_length] / 2
    path_buffer = reparse_data[:path_buffer]

    path = ''.encode('UTF-16LE')
    (offset..(offset + length - 1)).each do |i|
      # TODO: seems peculiar to be doing this 1 byte at a time and not 2
      path << path_buffer[i]
    end

    path
  end

  def self.readlink(link_name)
    begin
      handle = open_symlink(link_name)
      resolve_symlink(handle).encode('UTF-8')
    ensure
      if handle
        API.close_handle(handle)
      end
    end
  end
end

def symlink?(file_name)
  Windows.symlink?(file_name)
end

def symlink(src, dest, options = {})
  Windows.create_symbolic_link(dest, src)
end

def readlink(link_name)
  Windows.readlink(link_name)
end

target = File.expand_path('target')
link = File.expand_path('link')

FileUtils.touch(target)
FileUtils.rm_f(link)
symlink(target, link)

puts "File #{link}"
puts "  symlink? -> #{symlink?(link)}"
puts "  readlink -> #{readlink(link)}"

# # TODO: use standard Windows MAX_PATH, or 32767??
# MAX_PATH = 260

# # http://msdn.microsoft.com/en-us/library/windows/desktop/aa364962(v=vs.85).aspx
# GetFinalPathNameByHandle = Windows::API.new('GetFinalPathNameByHandleW', 'LPLL', 'L')
# # DWORD WINAPI GetFinalPathNameByHandle(
# #   _In_   HANDLE hFile,
# #   _Out_  LPTSTR lpszFilePath,
# #   _In_   DWORD cchFilePath,
# #   _In_   DWORD dwFlags
# # )
# # FILE_NAME_NORMALIZED = 0x0 - normalized drive name (default)
# # FILE_NAME_OPENED = 0x8 - opened file name (not normalized)
# # VOLUME_NAME_DOS = 0x0 - retun the path with drive letter (default)
# # VOLUME_NAME_GUID = 0x1 - return the path with volume GUID path instead of drive
# # VOLUME_NAME_NONE = 0x4 - return the path with no drive information
# # VOLUME_NAME_NT = 0x2 - return the path with volume device path
# def get_final_path_name_by_handle(file_handle, flags = 0x0)
#   buffer = 0.chr * MAX_PATH * 2
#   result = GetFinalPathNameByHandle.call(file_handle, buffer, buffer.size, flags)

#   # return code is 0 for fail OR size of buffer in TCHARs including terminating
#   # null if given buffer is too small
#   buffer = buffer.force_encoding('UTF-16LE')
#   return buffer.encode('UTF-8').strip unless result > MAX_PATH
#   raise new("GetFinalPathNameByHandle(#{file_handle}, #{buffer}, #{buffer.size}, #{flags.to_s(8)}")
# end

# # http://msdn.microsoft.com/en-us/library/windows/desktop/aa364989(v=vs.85).aspx
# GetShortPathName = Windows::API.new('GetShortPathNameW', 'PPL', 'L')
# # DWORD WINAPI GetShortPathName(
# #   _In_   LPCTSTR lpszLongPath,
# #   _Out_  LPTSTR lpszShortPath,
# #   _In_   DWORD cchBuffer
# # );
# def get_short_path_name(long_path)
#   buffer = 0.chr * MAX_PATH * 2
#   result = GetShortPathName.call(WideString.new(long_path), buffer, buffer.size)

#   buffer = buffer.force_encoding('UTF-16LE')
#   return buffer.encode('UTF-8').strip unless result > MAX_PATH
#   raise new("GetShortPathName(#{long_path}, #{buffer}, #{buffer.size}")
# end
