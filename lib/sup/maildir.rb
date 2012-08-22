require 'uri'
require 'set'

module Redwood

class Maildir < Source
  include SerializeLabelsNicely
  MYHOSTNAME = Socket.gethostname

  ## remind me never to use inheritance again.
  yaml_properties :uri, :usual, :archived, :sync_back, :id, :labels
  def initialize uri, usual=true, archived=false, sync_back=true, id=nil, labels=[]
    super uri, usual, archived, id
    @expanded_uri = Source.expand_filesystem_uri(uri)
    uri = URI(@expanded_uri)

    raise ArgumentError, "not a maildir URI" unless uri.scheme == "maildir"
    raise ArgumentError, "maildir URI cannot have a host: #{uri.host}" if uri.host
    raise ArgumentError, "maildir URI must have a path component" unless uri.path

    @sync_back = sync_back
    # sync by default if not specified
    @sync_back = true if @sync_back.nil?

    @dir = uri.path
    @labels = Set.new(labels || [])
    @mutex = Mutex.new
    @ctimes = { 'cur' => Time.at(0), 'new' => Time.at(0) }
  end

  def file_path; @dir end
  def self.suggest_labels_for path; [] end
  def is_source_for? uri; super || (uri == @expanded_uri); end

  def supported_labels?
    [:draft, :starred, :forwarded, :replied, :unread, :deleted]
  end

  def sync_back_enabled?
    @sync_back
  end

  def store_draft date, from_email, &block
    store_message_helper date, from_email, 'DS', &block
  end

  def store_message date, from_email, &block
    store_message_helper date, from_email, 'S', &block
  end

  def fn_for_offset id
    return File.join(@dir, id)
  end

  def store_message_helper date, from_email, labelstring, &block
    stored = false
    new_fn = new_maildir_basefn + ':2,' + labelstring
    Dir.chdir(@dir) do |d|
      tmp_path = File.join(@dir, 'tmp', new_fn)
      new_path = File.join(@dir, 'new', new_fn)
      begin
        sleep 2 if File.stat(tmp_path)

        File.stat(tmp_path)
      rescue Errno::ENOENT #this is what we want.
        begin
          File.open(tmp_path, 'wb') do |f|
            yield f #provide a writable interface for the caller
            f.fsync
          end

          File.safe_link tmp_path, new_path
          stored = true
        ensure
          File.unlink tmp_path if File.exists? tmp_path
        end
      end #rescue Errno...
    end #Dir.chdir

    stored
  end

  def each_raw_message_line id
    with_file_for(id) do |f|
      until f.eof?
        yield f.gets
      end
    end
  end

  def load_header id
    with_file_for(id) { |f| parse_raw_email_header f }
  end

  def load_message id
    with_file_for(id) { |f| RMail::Parser.read f }
  end

  def wrong_source? labels
    new_source = nil
    $config[:maildir_labels].each do |k,v|
      v.each do |lbl,i|
        if lbl.nil? or labels.member? lbl
          new_source = i
          break
        end
      end if v.any? { |lbl,i| i == @id }
    end if $config[:maildir_labels]
    new_source
  end

  def sync_back id, labels
    synchronize do
      debug "syncing back maildir message #{id} with flags #{labels.to_a}"
      new_source = (wrong_source? labels) || @id
      flags = maildir_reconcile_flags id, labels
      maildir_move_file id, new_source, flags
    end
  end

  def raw_header id
    ret = ""
    with_file_for(id) do |f|
      until f.eof? || (l = f.gets) =~ /^$/
        ret += l
      end
    end
    ret
  end

  def raw_message id
    with_file_for(id) { |f| f.read }
  end

  ## XXX use less memory
  def poll
    added = []
    deleted = []
    updated = []
    @ctimes.each do |d,prev_ctime|
      subdir = File.join @dir, d
      debug "polling maildir #{subdir}"
      raise FatalSourceError, "#{subdir} not a directory" unless File.directory? subdir
      ctime = File.ctime subdir
      next if prev_ctime >= ctime
      @ctimes[d] = ctime

      old_ids = benchmark(:maildir_read_index) { Enumerator.new(Index.instance, :each_source_info, self.id, "#{d}/").to_a }
      new_ids = benchmark(:maildir_read_dir) { Dir.glob("#{subdir}/*").map { |x| File.join(d,File.basename(x)) }.sort }
      added += new_ids - old_ids
      deleted += old_ids - new_ids
      debug "#{old_ids.size} in index, #{new_ids.size} in filesystem"
    end

    ## find updated mails by checking if an id is in both added and
    ## deleted arrays, meaning that its flags changed or that it has
    ## been moved, these ids need to be removed from added and deleted
    add_to_delete = del_to_delete = []
    map = Hash.new { |hash, key| hash[key] = [] }
    deleted.each do |id_del|
        map[maildir_data(id_del)[0]].push id_del
    end
    added.each do |id_add|
        map[maildir_data(id_add)[0]].each do |id_del|
          updated.push [ id_del, id_add ]
          add_to_delete.push id_add
          del_to_delete.push id_del
        end
    end
    added -= add_to_delete
    deleted -= del_to_delete
    debug "#{added.size} added, #{deleted.size} deleted, #{updated.size} updated"
    total_size = added.size+deleted.size+updated.size

    added.each_with_index do |id,i|
      yield :add,
      :info => id,
      :labels => @labels + maildir_labels(id) + [:inbox],
      :progress => i.to_f/total_size
    end

    deleted.each_with_index do |id,i|
      yield :delete,
      :info => id,
      :progress => (i.to_f+added.size)/total_size
    end

    updated.each_with_index do |id,i|
      yield :update,
      :old_info => id[0],
      :new_info => id[1],
      :labels => @labels + maildir_labels(id[1]),
      :progress => (i.to_f+added.size+deleted.size)/total_size
    end
    nil
  end

  def labels? id
    maildir_labels id
  end

  def maildir_labels id
    (seen?(id) ? [] : [:unread]) +
      (trashed?(id) ?  [:deleted] : []) +
      (flagged?(id) ? [:starred] : []) +
      (passed?(id) ? [:forwarded] : []) +
      (replied?(id) ? [:replied] : []) +
      (draft?(id) ? [:draft] : [])
  end

  def draft? id; maildir_data(id)[2].include? "D"; end
  def flagged? id; maildir_data(id)[2].include? "F"; end
  def passed? id; maildir_data(id)[2].include? "P"; end
  def replied? id; maildir_data(id)[2].include? "R"; end
  def seen? id; maildir_data(id)[2].include? "S"; end
  def trashed? id; maildir_data(id)[2].include? "T"; end

  def valid? id
    File.exists? File.join(@dir, id)
  end

private

  def new_maildir_basefn
    Kernel::srand()
    "#{Time.now.to_i.to_s}.#{$$}#{Kernel.rand(1000000)}.#{MYHOSTNAME}"
  end

  def with_file_for id
    fn = File.join(@dir, id)
    begin
      File.open(fn, 'rb') { |f| yield f }
    rescue SystemCallError, IOError => e
      raise FatalSourceError, "Problem reading file for id #{id.inspect}: #{fn.inspect}: #{e.message}."
    end
  end

  def maildir_data id
    id = File.basename id
    # Flags we recognize are DFPRST
    id =~ %r{^([^:]+):([12]),([A-Za-z]*)$}
    [($1 || id), ($2 || "2"), ($3 || "")]
  end

  def maildir_reconcile_flags id, labels
      new_flags = Set.new( maildir_data(id)[2].each_char )

      # Set flags based on labels for the six flags we recognize
      if labels.member? :draft then new_flags.add?( "D" ) else new_flags.delete?( "D" ) end
      if labels.member? :starred then new_flags.add?( "F" ) else new_flags.delete?( "F" ) end
      if labels.member? :forwarded then new_flags.add?( "P" ) else new_flags.delete?( "P" ) end
      if labels.member? :replied then new_flags.add?( "R" ) else new_flags.delete?( "R" ) end
      if not labels.member? :unread then new_flags.add?( "S" ) else new_flags.delete?( "S" ) end
      if labels.member? :deleted or labels.member? :killed then new_flags.add?( "T" ) else new_flags.delete?( "T" ) end

      ## Flags must be stored in ASCII order according to Maildir
      ## documentation
      new_flags.to_a.sort.join
  end

  def maildir_move_file orig_path, new_source_id, flags
    @mutex.synchronize do
      new_base = (flags.include?("S")) ? "cur" : "new"
      md_base, md_ver, md_flags = maildir_data orig_path

      return if md_flags == flags and new_source_id == @id

      new_source = SourceManager[new_source_id]

      new_loc = File.join new_base, "#{md_base}:#{md_ver},#{flags}"
      orig_path = File.join @dir, orig_path
      new_path  = File.join new_source.file_path, new_loc
      tmp_path  = File.join @dir, "tmp", "#{md_base}:#{md_ver},#{flags}"

      File.safe_link orig_path, tmp_path
      File.unlink orig_path
      File.safe_link tmp_path, new_path
      File.unlink tmp_path

      [new_source, new_loc]
    end
  end
end

end
