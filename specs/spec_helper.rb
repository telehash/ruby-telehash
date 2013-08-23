def data name
  data_file(name).read
end

def data_file name
  File.open((File.dirname(__FILE__) + "/data/#{name}"), "r")
end