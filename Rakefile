require 'bundler/gem_tasks'
require 'rake/testtask'

task :default => [:test]

Rake::TestTask.new do |t|
  t.libs.push 'lib'
  t.libs.push 'specs'
  t.test_files = FileList['specs/**/*_spec.rb']
#  t.options = "--verbose"
end
