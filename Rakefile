# frozen_string_literal: true

# bundler/gem_tasks provides build/install/release (the release workflow runs `rake release`, which
# builds from the gemspec version, skips re-tagging when the tag already exists, and `gem push`es).
require "bundler/gem_tasks"
require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.libs << "lib" << "test"
  t.test_files = FileList["test/**/test_*.rb"]
  t.warning = false
end

task default: :test
