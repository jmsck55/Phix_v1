--
-- pSQLite.e - A SQLite wrapper
--
--  Based on the work of Ray Smith, Chris Burch, and Tone Skoda, the main difference is that
--  phix can pass strings directly to C functions, so this saves at least one call to both
--  allocate_string() and free() in every routine, compared to an OE-compatible version.

-- (c) 2002 Ray Smith
-- smithr@ix.net.au
--
-- Name :       EuSQLite3 - an SQLite wrapper
-- Version :    0.3
-- Author :     Ray Smith
-- License :    None
-- Updated :    Chris Burch 21/12/2004
-- Updated :    August 2005 Tone Skoda

include builtins\serialize.e
include builtins\ptypes.e

global constant
                SQLITE_OK           = 0,    -- Successful result 
                SQLITE_ERROR        = 1,    -- SQL error or missing database 
                SQLITE_INTERNAL     = 2,    -- An internal logic error in SQLite 
                SQLITE_PERM         = 3,    -- Access permission denied 
                SQLITE_ABORT        = 4,    -- Callback routine requested an abort 
                SQLITE_BUSY         = 5,    -- The database file is locked 
                SQLITE_LOCKED       = 6,    -- A table in the database is locked 
                SQLITE_NOMEM        = 7,    -- A malloc() failed 
                SQLITE_READONLY     = 8,    -- Attempt to write a readonly database 
                SQLITE_INTERRUPT    = 9,    -- Operation terminated by sqlite_interrupt() 
                SQLITE_IOERR        = 10,   -- Some kind of disk I/O error occurred 
                SQLITE_CORRUPT      = 11,   -- The database disk image is malformed 
                SQLITE_NOTFOUND     = 12,   -- (Internal Only) Table or record not found 
                SQLITE_FULL         = 13,   -- Insertion failed because database is full 
                SQLITE_CANTOPEN     = 14,   -- Unable to open the database file 
                SQLITE_PROTOCOL     = 15,   -- Database lock protocol error 
                SQLITE_EMPTY        = 16,   -- (Internal Only) Database table is empty 
                SQLITE_SCHEMA       = 17,   -- The database schema changed 
                SQLITE_TOOBIG       = 18,   -- Too much data for one row of a table 
                SQLITE_CONSTRAINT   = 19,   -- Abort due to constraint violation 
                SQLITE_MISMATCH     = 20,   -- Data type mismatch 
                SQLITE_MISUSE       = 21,   -- Library used incorrectly
                SQLITE_NOLFS        = 22,   -- Uses OS features not supported on host
                SQLITE_AUTH         = 23,   -- Authorization denied
                SQLITE_ROW          = 100,  -- sqlite_step() has another row ready
                SQLITE_DONE         = 101   -- sqlite_step() has finished executing

global type sqlite3(object ptr)
--? an opaque pointer to an sqlite3 structure, or a string error message
-- an opaque pointer to an sqlite3 structure
-- you can instead just use an atom, which may be slightly faster
--  return atom(ptr) and ptr!=NULL
--? return string(ptr) or (atom(ptr) and ptr!=NULL)
    return atom(ptr)
end type

global type sqlite3_stmt(object ptr)
    return atom(ptr)
end type

procedure Abort(string msg)
    puts(1,msg)
    {} = wait_key()
    abort(0)
end procedure

atom sqlite3_dll = NULL

procedure open_sqlite3_dll(string dll_name="", bool fatal=true)
--
-- internal: via if sqlite3_dll=NULL then open_sqlite3_dll() end if, or
--           from sqlite3_open_dll as open_sqlite3_dll(dll_name,false).
--
sequence dll_names = {dll_name}, dll_paths = {}
string dll_path = ""
    if platform()=LINUX then
        if dll_name="" then
-- maybe:
--              string arch = iff(machine_bits()=32?"i386":"x86_64")
--              curl_dll_name = "/usr/lib/"&arch&"-linux-gnu/libcurl.so"
            dll_names = {"sqlite3.so","sqlite-3.so"}
        end if
    elsif platform()=WINDOWS then
        if dll_name="" then
-- maybe:
--              curl_dll_name = sprintf("LIBCURL.%d.SK.DLL",machine_bits())
            dll_names = {"sqlite3.dll"}
        end if
    else
        ?9/0 -- unknown platform
    end if
    for i=1 to length(dll_names) do
        dll_name = dll_names[i]
        sqlite3_dll = open_dll(dll_name)
        if sqlite3_dll!=NULL then exit end if
        if dll_path="" and dll_paths={} then
            sequence s = include_paths()
            for p=1 to length(s) do
                sequence sip = split_path(s[p])
                if sip[$]="builtins" then
                    sip[$..$] = {"demo","pSQLite"}
                    dll_path = join_path(sip,trailsep:=true)
                    if get_file_type(dll_path)=FILETYPE_DIRECTORY then
                        dll_paths = {dll_path}
                        exit
                    end if
                end if
            end for
        end if
        for j=1 to length(dll_paths) do
            dll_name = join_path({dll_paths[j],dll_names[i]})
            sqlite3_dll = open_dll(dll_name)
            if sqlite3_dll!=NULL then exit end if
        end for
        if sqlite3_dll!=NULL then exit end if
    end for
    if sqlite3_dll=NULL and fatal then
        string msg
        if platform()=LINUX then
            msg = "Fix your sqlite3 install.\n"&
                  "Get sqlite3.x.x.so from www.sqlite3.org\n"&
                  "Put it into /usr/lib, and run ldconfig\n"&
                  "Create a symlink in /usr/lib, sqlite3.so, pointing to sqlite-3.x.x.so\n"&
                  "Run again\n"
        elsif platform()=WINDOWS then
            msg = "Install sqlite3.dll, from www.sqlite.org, into windows\\system32\n"&
                  "or the application directory\n"
        else
            ?9/0 -- unknown platform
        end if
        Abort(msg)
    end if
end procedure

constant
--              SQLITE_STATIC       = 0,
                SQLITE_TRANSIENT    = -1

constant W = machine_word()     -- (4 or 8)

constant
         D  = C_DOUBLE, 
         I  = C_INT,
         P  = C_POINTER, 
         $
--       F  = C_FLOAT,      -- NB: VM/pcfunc.e may not be up to this.. [edited 25/2/16]
--       L  = C_LONG,
--       U  = C_UINT,
--       UC = C_UCHAR,
--       UL = C_ULONG,

function link_c_func(atom dll, sequence name, sequence args, atom result)
    if dll=NULL then ?9/0 end if
--  integer rid = define_c_func(dll, "+" & name, args, result)
    integer rid = define_c_func(dll, name, args, result)
    if rid<1 then Abort("cannot link "&name) end if
    return rid
end function

function link_c_proc(atom dll, sequence name, sequence args)
    if dll=NULL then ?9/0 end if
--  integer rid = define_c_proc(dll, "+" & name, args)
    integer rid = define_c_proc(dll, name, args)
    if rid<1 then Abort("cannot link "&name) end if
    return rid
end function

global function sqlite3_open_dll(string dll_name="")
-- optional, see docs.
bool res = true
    if sqlite3_dll=NULL then
        open_sqlite3_dll(dll_name, false)
        res = (sqlite3_dll!=NULL)
    end if
    return res
end function

integer xsqlite3_libversion = NULL

global function sqlite3_libversion(bool bAsNumSeq=false)
    if xsqlite3_libversion=NULL then
        if sqlite3_dll=NULL then open_sqlite3_dll() end if
        xsqlite3_libversion = link_c_func(sqlite3_dll, "+sqlite3_libversion", {}, P)
    end if
    atom addr = c_func(xsqlite3_libversion,{})
--  return peek_sequence(addr, SQLITE_MAX_VERSION_LENGTH)
    object res = peek_string(addr)
    if bAsNumSeq then
--?{1,res}
        res = substitute(res,".","-")
--?{2,res}
        {res} = scanf(res,"%d-%d-%d")
--      res = scanf(res,"%d-%d-%d")
--?{3,res}
--      {res} = res
--?{4,res}
    end if
    return res
end function

integer xsqlite3_close = NULL

global procedure sqlite3_close(atom db)
    if xsqlite3_close=NULL then
        xsqlite3_close = link_c_proc(sqlite3_dll, "+sqlite3_close", {P})
    end if
    c_proc(xsqlite3_close,{db})
end procedure

-----------------------------
-- Routine : sqlite3_free
-- Syntax : sqlite3_free(atom addr)
-- Description : Frees memory allocated from mprintf() or vmprintf().
-- Used internally by sqlite
-----------------------------
integer xsqlite3_free = NULL
--global -???
procedure sqlite3_free(atom addr)
    if xsqlite3_free=NULL then
        xsqlite3_free = link_c_proc(sqlite3_dll, "+sqlite3_free", {P})
    end if
    c_proc(xsqlite3_free,{addr})
end procedure


integer xsqlite3_errmsg = NULL

global function sqlite3_errmsg(atom db)
    if xsqlite3_errmsg=NULL then
        xsqlite3_errmsg = link_c_func(sqlite3_dll, "+sqlite3_errmsg", {P}, P)
    end if
    atom message_addr = c_func(xsqlite3_errmsg, {db})
    string message = peek_string(message_addr)
--  sqlite3_free(message_addr) - (it specifically says not to do this)
    return message
end function

function default_fatal(string cmd, integer err_no, string err_desc)
-- default fatal error handler - you can override this
    printf(1, "Fatal SQLite Error %d: %s \nWhen Executing: %s\n\n", {err_no, err_desc, cmd})
    return 1/0 -- to see call stack
end function
global constant SQLITE3_FATAL = routine_id("default_fatal")

function non_fatal(string cmd, integer err_no, string err_desc)
    return {err_no, err_desc, cmd}
end function
global constant SQLITE3_NON_FATAL = routine_id("non_fatal")

-- exception handler:
-- you can set it to your own handler, or SQLITE3_NON_FATAL

integer sqlite_fatal_id = SQLITE3_FATAL

global procedure sqlite3_set_fatal_id(integer rid)
    sqlite_fatal_id = rid
end procedure

function fatal(atom db, string cmd, integer err_no, object err_desc=0)
-- does not return by default, but can be configured so that it does.
    if err_desc=0 then err_desc = sqlite3_errmsg(db) end if
    if db>0 then sqlite3_close(db) end if
    return call_func(sqlite_fatal_id, {cmd, err_no, err_desc})
end function

atom xsqlite3_open = NULL

global function sqlite3_open(string filename)
    if xsqlite3_open=NULL then
        if sqlite3_dll=NULL then open_sqlite3_dll() end if
        xsqlite3_open = link_c_func(sqlite3_dll, "+sqlite3_open", {P,P}, I)
    end if
    atom db_addr = allocate(W)
    integer err_no = c_func(xsqlite3_open, {filename, db_addr})
    atom db = peek4u(db_addr)
    free(db_addr)
--  sqlite_last_err_no = err_no
--  sqlite_last_err_desc = ""
    if err_no!=SQLITE_OK then
--      sqlite_last_err_desc = sqlite3_errmsg(db)
        return fatal(db, "sqlite3_open()", err_no)
    end if
    return db
end function

-- might need this one day
--global 
function sqlite3_peek_strings(integer n, atom ptr)
    sequence res = {}
    for i=1 to n do
        atom p = peekNS(ptr,W,false)
        string s = peek_string(p)
        res = append(res,s)
        ptr += W
    end for
    return res
end function
-----------------------------
-- sqlite_exec_callback
-----------------------------
function sqlite_exec_callback(atom user_data, integer ncols, atom data_ptr, atom col_names_ptr)
    sequence data = sqlite3_peek_strings(ncols,data_ptr)
    sequence cols = sqlite3_peek_strings(ncols,col_names_ptr)
    integer rid
    {rid,user_data} = peekNS({user_data,2},W,false)
    integer ret = call_func(rid,{data,cols,user_data})
    return ret
end function
constant exec_cb = call_back({'+',routine_id("sqlite_exec_callback")})

integer xsqlite3_exec = NULL
global string sqlite_last_exec_err = ""

global function sqlite3_exec(sqlite3 db, string cmd, integer rid=0, atom user_data=NULL)
    if xsqlite3_exec=NULL then
        xsqlite3_exec = link_c_func(sqlite3_dll, "+sqlite3_exec", {P,P,P,P,P}, I)
    end if
    atom err_ptr_addr = allocate(W)
    pokeN(err_ptr_addr,0,W)
    integer ret
    if rid=0 then
        ret = c_func(xsqlite3_exec,{db, cmd, NULL, NULL, err_ptr_addr})
    else
        atom rud = allocate(W*2)
        pokeN(rud,{rid,user_data},W)
        ret = c_func(xsqlite3_exec,{db, cmd, exec_cb, rud, err_ptr_addr})
        free(rud)
    end if
    atom err_addr = peek4u(err_ptr_addr)
    free(err_ptr_addr)

--  sqlite_last_err_no = SQLITE_OK
--  sqlite_last_err_desc = ""
    if ret!=SQLITE_OK then
--      sqlite_last_err_no = ret
--      object err_desc = 0
        if err_addr>0 then
--          sqlite_last_err_desc = peek_sequence(err_addr, SQLITE_MAX_ERR_LENGTH)
--          err_desc = peek_string(err_addr)
            sqlite_last_exec_err = peek_string(err_addr)
-- better?: string err = peek_string(err_addr)
            sqlite3_free(err_addr)
--          return {ret,err}
        else
            sqlite_last_exec_err = "(NULL)"
        end if
--      if not find(ret, {SQLITE_ABORT, SQLITE_BUSY}) then
--          return fatal(db, `sqlite_exec("` & cmd & `")`, ret, err_desc)
--      end if
    end if
    return ret
end function

integer xsqlite3_get_autocommit = NULL

global function sqlite3_get_autocommit(sqlite3 db)
    if xsqlite3_get_autocommit=NULL then
        xsqlite3_get_autocommit = link_c_func(sqlite3_dll, "+sqlite3_get_autocommit", {P}, I)
    end if
    bool ret = c_func(xsqlite3_get_autocommit,{db})
    return ret
end function

integer xsqlite3_free_table = NULL
--global --??
procedure sqlite3_free_table(atom data_addr)
    if xsqlite3_free_table=NULL then
        xsqlite3_free_table = link_c_proc(sqlite3_dll, "+sqlite3_free_table", {P})
    end if
    c_proc(xsqlite3_free_table,{data_addr})
end procedure

integer xsqlite3_get_table = NULL

global function sqlite3_get_table(sqlite3 db, string cmd)
    if xsqlite3_get_table=NULL then
        xsqlite3_get_table = link_c_func(sqlite3_dll, "+sqlite3_get_table", {P,P,P,I,I,P}, I)
    end if
    atom data_ptr_addr = allocate(W*4)
    atom row_addr = data_ptr_addr+W
    atom col_addr = data_ptr_addr+2*W
    atom err_ptr_addr = data_ptr_addr+3*W
    mem_set(data_ptr_addr, 0, W*4)

    integer ret = c_func(xsqlite3_get_table,{db, cmd, data_ptr_addr, row_addr, col_addr, err_ptr_addr})
    atom data_addr = peek4u(data_ptr_addr)
    integer row = peek4u(row_addr)
    integer col = peek4u(col_addr)
    atom err_addr = peek4u(err_ptr_addr)
    free(data_ptr_addr)

--  sqlite_last_err_no = SQLITE_OK
    if ret!=SQLITE_OK then
        object err_desc = 0
--      sqlite_last_err_no = ret
        if err_addr>0 then
--          sqlite_last_err_desc = peek_sequence(err_addr, SQLITE_MAX_ERR_LENGTH)
            err_desc = peek_string(err_addr)
            sqlite3_free(err_addr)
        end if
        if not find(ret, {SQLITE_ABORT, SQLITE_BUSY}) then
            return fatal(db, `sqlite_get_table("` & cmd & `")`, ret, err_desc)
        end if
        return ret
    end if

    sequence data = {}
    if row>0 then
        atom tmp_ptr_addr = data_addr
        for r=0 to row do
            sequence tmp_row = {}
            string tmp_field
            for c=1 to col do
                atom field_addr = peek4u(tmp_ptr_addr)
                if field_addr!=0 then
                    tmp_field = peek_string(field_addr)
                else
                    tmp_field = ""
                end if
                tmp_ptr_addr += W
                tmp_row = append(tmp_row, tmp_field)
            end for
            data = append(data, tmp_row)
        end for
    end if

    sqlite3_free_table(data_addr)

    return data
end function

integer xsqlite3_prepare = NULL

global function sqlite3_prepare(sqlite3 db, string cmd)

    if xsqlite3_prepare=NULL then
        xsqlite3_prepare = link_c_func(sqlite3_dll, "+sqlite3_prepare", {P,P,I,P,P}, I)
--      xsqlite3_prepare = link_c_func(sqlite3_dll, "+sqlite3_prepare_v2", {P,P,I,P,P}, I)
    end if

    atom stmt_ptr = allocate(W)
    pokeN(stmt_ptr,0,W)

    integer ret = c_func(xsqlite3_prepare,{db, cmd, length(cmd), stmt_ptr, NULL})

    sqlite3_stmt pStmt = peek4u(stmt_ptr)
    free(stmt_ptr)

--  sqlite_last_err_no = ret
--  sqlite_last_err_desc = ""
    if ret!=SQLITE_OK then
--      sqlite_last_err_no = ret
--      sqlite_last_err_desc = sqlite3_errmsg(db)
        return fatal(db, `sqlite_prepare("` & cmd & `")`, ret)
    end if

    return pStmt
end function

integer xsqlite3_bind_parameter_count = NULL

global function sqlite3_bind_parameter_count(sqlite3_stmt pStmt)
    if xsqlite3_bind_parameter_count=NULL then
        xsqlite3_bind_parameter_count = link_c_func(sqlite3_dll, "+sqlite3_bind_parameter_count", {P}, I)
    end if
    integer ret = c_func(xsqlite3_bind_parameter_count,{pStmt})
    return ret
end function

integer xsqlite3_bind_parameter_index = NULL

global function sqlite3_bind_parameter_index(sqlite3_stmt pStmt, string zName)
    if xsqlite3_bind_parameter_index=NULL then
        xsqlite3_bind_parameter_index = link_c_func(sqlite3_dll, "+sqlite3_bind_parameter_index", {P,P}, I)
    end if
    integer ret = c_func(xsqlite3_bind_parameter_index,{pStmt,zName})
    return ret
end function

integer xsqlite3_bind_parameter_name = NULL

global function sqlite3_bind_parameter_name(sqlite3_stmt pStmt, integer n)
    if xsqlite3_bind_parameter_name=NULL then
        xsqlite3_bind_parameter_name = link_c_func(sqlite3_dll, "+sqlite3_bind_parameter_name", {P,I}, P)
    end if
    atom pName = c_func(xsqlite3_bind_parameter_name,{pStmt,n})
    string res = ""
    if pName!=NULL then
        res = peek_string(pName)
        --DEV I assume it should not sqlite3_free(pName) here...
    end if
    return res
end function

integer xsqlite3_bind_int = NULL

--global procedure sqlite3_bind_int(sqlite3_stmt pStmt, integer idx, integer val)
global procedure sqlite3_bind_int(sqlite3_stmt pStmt, atom_string idx, integer val)
--global procedure sqlite3_bind_int(atom pStmt, integer idx, integer val)
    if xsqlite3_bind_int=NULL then
        xsqlite3_bind_int = link_c_func(sqlite3_dll, "+sqlite3_bind_int", {P,I,I}, I)
    end if
    if string(idx) then
        idx = sqlite3_bind_parameter_index(pStmt, idx)
    end if

    integer ret = c_func(xsqlite3_bind_int,{pStmt, idx, val})

--  sqlite_last_err_no = ret
--  sqlite_last_err_desc = ""
    if ret!=SQLITE_OK then
--      sqlite_last_err_desc = sqlite3_errmsg(db)
        {} = fatal(NULL, "sqlite_bind_int()", ret)
    end if

end procedure

integer xsqlite3_bind_double = NULL

--global procedure sqlite3_bind_double(sqlite3_stmt pStmt, integer idx, atom val)
global procedure sqlite3_bind_double(sqlite3_stmt pStmt, atom_string idx, atom val)
    if xsqlite3_bind_double=NULL then
        xsqlite3_bind_double = link_c_func(sqlite3_dll, "+sqlite3_bind_double", {P,I,D}, I)
    end if
    if string(idx) then
        idx = sqlite3_bind_parameter_index(pStmt, idx)
    end if

    integer ret = c_func(xsqlite3_bind_double,{pStmt, idx, val})

--  sqlite_last_err_no = ret
--  sqlite_last_err_desc = ""
    if ret!=SQLITE_OK then
--      sqlite_last_err_desc = sqlite3_errmsg(db)
        {} = fatal(NULL, "sqlite_bind_double()", ret)
    end if

end procedure

integer xsqlite3_bind_text = NULL

--global procedure sqlite3_bind_text(sqlite3_stmt pStmt, integer idx, string val)
global procedure sqlite3_bind_text(sqlite3_stmt pStmt, atom_string idx, string val)
--global procedure sqlite3_bind_text(atom pStmt, integer idx, string val)
    if xsqlite3_bind_text=NULL then
        xsqlite3_bind_text = link_c_func(sqlite3_dll, "+sqlite3_bind_text", {P,I,P,I,P}, I)
    end if
    if string(idx) then
        idx = sqlite3_bind_parameter_index(pStmt, idx)
    end if
    integer ret = c_func(xsqlite3_bind_text,{pStmt, idx, val, length(val), SQLITE_TRANSIENT})
--  sqlite_last_err_no = ret
--  sqlite_last_err_desc = ""
    if ret!=SQLITE_OK then
--      sqlite_last_err_desc = sqlite3_errmsg(db)
        {} = fatal(NULL, "sqlite_bind_text()", ret)
    end if
end procedure

integer xsqlite3_bind_blob = NULL

--global procedure sqlite3_bind_blob(sqlite3_stmt pStmt, integer idx, object val)
global procedure sqlite3_bind_blob(sqlite3_stmt pStmt, atom_string idx, object val)
    if xsqlite3_bind_blob=NULL then
        xsqlite3_bind_blob = link_c_func(sqlite3_dll, "+sqlite3_bind_blob", {P,I,P,I,P}, I)
    end if
    if string(idx) then
        idx = sqlite3_bind_parameter_index(pStmt, idx)
    end if
    sequence val_string = serialize(val)
    atom val_addr = allocate_string(val_string)

    integer ret = c_func(xsqlite3_bind_blob,{pStmt, idx, val_addr, length(val_string), SQLITE_TRANSIENT})

    free(val_addr)
    val_string = {}     -- (there is very little point cluttering up ex.err files with this filth!)
--  sqlite_last_err_no = ret
--  sqlite_last_err_desc = ""
    if ret!=SQLITE_OK then
--      sqlite_last_err_desc = sqlite3_errmsg(db)
        {} = fatal(NULL, "sqlite_bind_blob()", ret)
    end if
end procedure

integer xsqlite3_bind_null = NULL

--global procedure sqlite3_bind_null(sqlite3_stmt pStmt, integer idx)
global procedure sqlite3_bind_null(sqlite3_stmt pStmt, atom_string idx)
    if xsqlite3_bind_null=NULL then
        xsqlite3_bind_null = link_c_func(sqlite3_dll, "+sqlite3_bind_null", {P,I}, I)
    end if
    if string(idx) then
        idx = sqlite3_bind_parameter_index(pStmt, idx)
    end if
    integer ret = c_func(xsqlite3_bind_null,{pStmt, idx})
    if ret!=SQLITE_OK then
        {} = fatal(NULL, "sqlite_bind_blob()", ret)
    end if
end procedure

integer xsqlite3_step = NULL

global function sqlite3_step(sqlite3_stmt pStmt)
--global function sqlite3_step(atom pStmt)
    if xsqlite3_step=NULL then
        xsqlite3_step = link_c_func(sqlite3_dll, "+sqlite3_step", {P}, I)
    end if

    integer ret = c_func(xsqlite3_step,{pStmt})

--  sqlite_last_err_no = ret
--  sqlite_last_err_desc = ""
--  if ret=SQLITE_DONE
--  or ret=SQLITE_ROW
--  or ret=SQLITE_BUSY then
      -- do nothing
--  elsif ret=SQLITE_ERROR
--     or ret=SQLITE_MISUSE then
    if ret=SQLITE_ERROR
    or ret=SQLITE_MISUSE then
--      sqlite_last_err_desc = sqlite3_errmsg(db)
        return fatal(NULL, "sqlite_step()", ret)
    end if

    return ret
end function

integer xsqlite3_column_count = NULL

global function sqlite3_column_count(sqlite3_stmt pStmt)
    if xsqlite3_column_count=NULL then
        xsqlite3_column_count = link_c_func(sqlite3_dll, "+sqlite3_column_count", {P}, I)
    end if
    int res = c_func(xsqlite3_column_count,{pStmt})
    return res
end function

integer xsqlite3_data_count = NULL

global function sqlite3_data_count(sqlite3_stmt pStmt)
    if xsqlite3_data_count=NULL then
        xsqlite3_data_count = link_c_func(sqlite3_dll, "+sqlite3_data_count", {P}, I)
    end if
    int res = c_func(xsqlite3_data_count,{pStmt})
    return res
end function

global constant SQLITE_INTEGER  = 1,
                SQLITE_FLOAT    = 2,
                SQLITE_TEXT     = 3,
                SQLITE_BLOB     = 4,
                SQLITE_NULL     = 5

integer xsqlite3_column_type = NULL

global function sqlite3_column_type(sqlite3_stmt pStmt, integer column)
    if xsqlite3_column_type=NULL then
        xsqlite3_column_type = link_c_func(sqlite3_dll, "+sqlite3_column_type", {P,I}, I)
    end if
    integer res = c_func(xsqlite3_column_type,{pStmt, column-1})
    return res
end function

integer xsqlite3_column_decltype = NULL

global function sqlite3_column_decltype(sqlite3_stmt pStmt, integer column)
    if xsqlite3_column_decltype=NULL then
        xsqlite3_column_decltype = link_c_func(sqlite3_dll, "+sqlite3_column_decltype", {P,I}, P)
    end if
    atom pRes = c_func(xsqlite3_column_decltype,{pStmt, column-1})
    string res = iff(pRes=NULL?"":peek_string(pRes))
    return res
end function

integer xsqlite3_column_name = NULL

global function sqlite3_column_name(sqlite3_stmt pStmt, integer column)
    if xsqlite3_column_name=NULL then
        xsqlite3_column_name = link_c_func(sqlite3_dll, "+sqlite3_column_name", {P,I}, P)
    end if
    atom pRes = c_func(xsqlite3_column_name,{pStmt, column-1})
    string res = iff(pRes=NULL?"":peek_string(pRes))
    return res
end function

integer xsqlite3_column_bytes = NULL

--global 
function sqlite3_column_bytes(sqlite3_stmt pStmt, integer column)
    if xsqlite3_column_bytes=NULL then
        xsqlite3_column_bytes = link_c_func(sqlite3_dll, "+sqlite3_column_bytes", {P,I}, P)
    end if
    integer res = c_func(xsqlite3_column_bytes,{pStmt, column-1})
    return res
end function

integer xsqlite3_column_int = NULL

global function sqlite3_column_int(sqlite3_stmt pStmt, integer column)
    if xsqlite3_column_int=NULL then
        xsqlite3_column_int = link_c_func(sqlite3_dll, "+sqlite3_column_int", {P,I}, I)
    end if
    int res = c_func(xsqlite3_column_int,{pStmt, column-1})
    return res
end function

integer xsqlite3_column_double = NULL

global function sqlite3_column_double(sqlite3_stmt pStmt, integer column)
    if xsqlite3_column_double=NULL then
        xsqlite3_column_double = link_c_func(sqlite3_dll, "+sqlite3_column_double", {P,I}, D)
    end if
    atom res = c_func(xsqlite3_column_double,{pStmt, column-1})
    return res
end function

integer xsqlite3_column_text = NULL

global function sqlite3_column_text(sqlite3_stmt pStmt, integer column)
    if xsqlite3_column_text=NULL then
        xsqlite3_column_text = link_c_func(sqlite3_dll, "+sqlite3_column_text", {P,I}, P)
    end if
    atom addr = c_func(xsqlite3_column_text,{pStmt, column-1})
    string res = ""
    if addr!=NULL then
        integer nBytes = sqlite3_column_bytes(pStmt, column)
        res = peek({addr, nBytes})
    end if
    return res
end function

integer xsqlite3_column_blob = NULL

global function sqlite3_column_blob(sqlite3_stmt pStmt, integer column)
    if xsqlite3_column_blob=NULL then
        xsqlite3_column_blob = link_c_func(sqlite3_dll, "+sqlite3_column_blob", {P,I}, P)
    end if
    atom addr = c_func(xsqlite3_column_blob,{pStmt, column-1})
    object res = NULL
    if addr!=NULL then
        integer nBytes = sqlite3_column_bytes(pStmt, column)
        if nBytes!=0 then
            sequence val_string = peek({addr, nBytes})
            res = deserialize(val_string)
        end if
    end if
    return res
end function

integer xsqlite3_reset = NULL

global procedure sqlite3_reset(sqlite3_stmt pStmt)
    if xsqlite3_reset=NULL then
        xsqlite3_reset = link_c_func(sqlite3_dll, "+sqlite3_reset", {P}, I)
    end if
    
    integer ret = c_func(xsqlite3_reset,{pStmt})

--  sqlite_last_err_no = ret
--  sqlite_last_err_desc = ""
    if ret!=SQLITE_OK then
--      sqlite_last_err_desc = sqlite3_errmsg(db)
        {} = fatal(NULL, "sqlite_reset()", ret)
    end if
end procedure


integer xsqlite3_finalize = NULL

global function sqlite3_finalize(sqlite3_stmt pStmt)
    if xsqlite3_finalize=NULL then
        xsqlite3_finalize = link_c_func(sqlite3_dll, "+sqlite3_finalize", {P}, I)
    end if

    integer ret = c_func(xsqlite3_finalize,{pStmt})

--  sqlite_last_err_no = ret
--  sqlite_last_err_desc = ""
    if ret!=SQLITE_OK then
--      sqlite_last_err_desc = sqlite3_errmsg(db)
        if ret!=SQLITE_ABORT then
            return fatal(NULL, "sqlite_finalize()", ret)
        end if
    end if
    return ret
end function

integer xsqlite3_last_insert_rowid = NULL

global function sqlite3_last_insert_rowid(sqlite3 db)
-- sqlite3_last_insert_rowid(sqlite3*);
--gets the last inserted row_id from open database db
--remember, to get the last inserted row, need to  work on an open database, where the data has just been inserted
-------------------------------------------------------------------------------------
    if xsqlite3_last_insert_rowid=NULL then
        xsqlite3_last_insert_rowid = link_c_func(sqlite3_dll, "+sqlite3_last_insert_rowid", {P}, I)
    end if

    atom row_id = c_func(xsqlite3_last_insert_rowid, {db})

    return row_id
end function

integer xsqlite3_changes = NULL

global function sqlite3_changes(sqlite3 db)
    if xsqlite3_changes=NULL then
        xsqlite3_changes = link_c_func(sqlite3_dll, "+sqlite3_changes", {P}, I)
    end if
    integer res = c_func(xsqlite3_changes, {db})
    return res
end function

integer xsqlite3_total_changes = NULL

global function sqlite3_total_changes(sqlite3 db)
    if xsqlite3_total_changes=NULL then
        xsqlite3_total_changes = link_c_func(sqlite3_dll, "+sqlite3_total_changes", {P}, I)
    end if
    integer res = c_func(xsqlite3_total_changes, {db})
    return res
end function

-- Intro :
--This guide will give you a quick introduction on how to use euSQLite in 
--your programs. <br><br>
--
--There is some information in the base SQLite docs found in the sqldocs\
--directory which you need to read as well.  You should take the time to
--read at least the FAQ.htm, Query.htm and sqlite_util.htm.<br><br>
--
--
--The Basic Structure<br>
---------------------<br><br>
--
--This is the skeleton of a typical euSQLite program.<br>
--
-----------------------------------------<br>
--include "eusqlite.ew"<br><br>
--
--atom db<br>
--sequence data<br><br>
--
--db = sqlite_open("{filename_of_your_database",0)<br><br>
--
--... do some processing / user input etc<br><br>
--
--data = sqlite_get_table(db, "{SQL statements go here}")<br>
--if sqlite_last_err_no != SQLITE_OK then<br>
--... do some error processing<br>
--end if<br><br>
--
--... do some more processing / user input etc<br><br>
--
--sqlite_close(db)<br><br>
--
-----------------------------------------<br><br>
--
--It basically comes down to:<br><br>
--
--* Include "euSQLite.ew"<br><br>
--
--* Open your database - sqlite_open()<br><br>
--
--* Execute SQL statements - sqlite_get_table()<br><br>
--
--* Close your database - sqlite_close()<br><br>

--*************************************************
-- Globals
--*************************************************

--global library versions - update this for sqlite updates
--global sequence SQLITE3_LINUX_LIB_VER,
--              SQLITE3_WIN_LIB_VER
----SQLITE3_LINUX_LIB_VER = "sqlite-3.3.6.so"
--SQLITE3_LINUX_LIB_VER = "sqlite-3.so"
--SQLITE3_WIN_LIB_VER = `..\dlls\sqlite3.dll`
--SQLITE3_WIN_LIB_VER = "sqlite3.dll"

--global integer sqlite_last_err_no = SQLITE_OK
--global sequence sqlite_last_err_desc = ""


-- the maximum length of an individual column returned from exec and get_table
--global integer SQLITE_MAX_FIELD_LENGTH = 32768

-- the maximum length of error messages 
--global integer SQLITE_MAX_ERR_LENGTH = 128

-- the maximum length of the version string
--global integer SQLITE_MAX_VERSION_LENGTH = 64

---------------------------------------------------------------------------------------
--global function sqlite_query_database(string database, string cmd)
----a universal get info from a database function
---- note this can be significantly slower...
---------------------------------------------------------------------------------------
--sequence data
----integer err_no
--integer wk_void
--
--  sqlite3 sql_db = sqlite3_open(database)
--  if sql_db<=0 then
--      puts(1,"Unable to open database " & database)
--  end if
--
--  data = sqlite3_get_table(sql_db, cmd)
----SUG:
----    {integer err_no, sequence data} = sqlite3_get_table(sql_db, cmd)
--  if sqlite_last_err_no!=SQLITE_OK then
--  --      errors here originally handled by my own handlers, replaced here by puts
--      puts(1,"Error in " & database & " : " & sqlite_last_err_desc)
--      wk_void = wait_key()
--      if wk_void='?' then
--          position(1,1)
--          puts(1, cmd)
--          wk_void = wait_key()
--      end if
--  end if
--
--  sqlite3_close(sql_db)
--
--  --remember 1st row of data is the headers
--  --will pass it back, but in most cases just discard it
--
--  return data
--end function

