require 'win32/file'
require 'fileutils'

target = File.expand_path('target')
link = File.expand_path('link')

FileUtils.touch(target)
FileUtils.rm_f(link)
File.symlink(target, link)

puts "File #{link}"
puts "  symlink? -> #{File.symlink?(link)}"
puts "  readlink -> #{File.readlink(link)}"
