require 'fileutils'
require 'net/http'
require 'uri'
require 'json'

class Grafana
  attr_accessor :host
  attr_accessor :key
  attr_accessor :dashboards_path

  def initialize(host, key, dashboards_path = './dashboards')
    self.host = host.end_with?('/') ? host.chop : host
    self.key = key
    self.dashboards_path = dashboards_path
  end

  def run
    prepare
    export_all(dashboards)
  end

  private

  def prepare
    FileUtils.rm_rf(dashboards_path) if Dir.exist?(dashboards_path)
    FileUtils.mkdir_p(dashboards_path)
    puts "Reset #{dashboards_path} finished!"
  end

  def dashboards
    http_get_methed('/api/search?query=&').map { |item| item['uid'] }
  end

  def dashboard(uid)
    http_get_methed("/api/dashboards/uid/#{uid}")
  end

  def export_dashboard(uid)
    File.open("#{dashboards_path}/#{dashboard(uid)['meta']['slug']}-#{uid}.json", 'w') do |f|
      f.write(JSON.pretty_generate(dashboard(uid)))
      puts "#{dashboards_path}/#{dashboard(uid)['meta']['slug']}-#{uid}.json ..."
    end
  end

  def export_all(uids)
    uids.each do |u|
      export_dashboard(u)
    end
  end

  def http_get_methed(uri)
    url = URI("#{host}#{uri}")
    http = Net::HTTP.new(url.host, url.port)
    header = { 'Authorization': "Bearer #{key}" }
    JSON.parse(http.get(url, header).read_body)
  end
end

if __FILE__ == $PROGRAM_NAME
  host = 'http://grafana.devops.com'
  key = 'eyJrIjoibVRiaHNvZzBaMDVMOVZDbGl3QjRDendLWDM0bDRLUjYiLCJuIjoiYWRtaW4iLCJpZCI6MX0='

  g = Grafana.new(host, key)
  g.run
end
