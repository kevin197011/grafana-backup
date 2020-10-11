# frozen_string_literal: true

task default: :fmt

task :fmt do
  system 'rubocop -A'
end

task push: :fmt do
  system 'git add .'
  system 'git commit -m "update"'
  system 'git push'
end

task :run do
  system 'ruby run.rb'
end
