package at.tugraz.netguard;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.TypedArray;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Handler;
import android.preference.PreferenceManager;
import android.support.v4.content.ContextCompat;
import android.support.v7.widget.RecyclerView;
import android.text.SpannableString;
import android.text.style.ForegroundColorSpan;
import android.util.Log;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.SubMenu;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.CursorAdapter;
import android.widget.Filter;
import android.widget.Filterable;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.PopupMenu;
import android.widget.TextView;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import eu.faircode.netguard.DatabaseHelper;
import eu.faircode.netguard.R;
import eu.faircode.netguard.Rule;
import eu.faircode.netguard.Util;

public class AdapterSecurity extends RecyclerView.Adapter<AdapterSecurity.ViewHolder> implements Filterable {
    private static final String TAG = "NetGuard.Adapter";

    private Activity context;
    private LayoutInflater inflater;
    private RecyclerView rv;
    private int colorText;
    private int colorChanged;
    private int colorOn;
    private int colorOff;
    private int colorGrayed;
    private int iconSize;
    private boolean live = true;
    private List<Rule> listAll = new ArrayList<>();
    private List<Rule> listFiltered = new ArrayList<>();

    private ExecutorService executor = Executors.newCachedThreadPool();

    public static class ViewHolder extends RecyclerView.ViewHolder {
        public View view;

        public LinearLayout llApplication;
        public ImageView ivIcon;
        public ImageView ivExpander;
        public TextView tvName;

        public LinearLayout llConfiguration;
        public TextView tvUid;
        public TextView tvPackage;
        public TextView tvVersion;
        public TextView tvInternet;
        public TextView tvDisabled;

        public ListView lvConnections;
        public ImageButton btnClearConnections;

        public ListView lvKeywords;
        public ImageButton btnAddKeyword;

        public IconLoader iconLoader = null;

        public ViewHolder(View itemView) {
            super(itemView);
            view = itemView;

            llApplication = itemView.findViewById(R.id.llApplication);
            ivIcon = itemView.findViewById(R.id.ivIcon);
            ivExpander = itemView.findViewById(R.id.ivExpander);
            tvName = itemView.findViewById(R.id.tvName);

            llConfiguration = itemView.findViewById(R.id.llConfiguration);
            tvUid = itemView.findViewById(R.id.tvUid);
            tvPackage = itemView.findViewById(R.id.tvPackage);
            tvVersion = itemView.findViewById(R.id.tvVersion);
            tvInternet = itemView.findViewById(R.id.tvInternet);
            tvDisabled = itemView.findViewById(R.id.tvDisabled);

            lvConnections = itemView.findViewById(R.id.lvConnections);
            btnClearConnections = itemView.findViewById(R.id.btnClearConnections);

            btnAddKeyword = itemView.findViewById(R.id.btnAddKeyword);
            lvKeywords = itemView.findViewById(R.id.lvKeywords);
        }
    }

    public AdapterSecurity(Activity context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        this.context = context;
        this.inflater = LayoutInflater.from(context);

        if (prefs.getBoolean("dark_theme", false))
            colorChanged = Color.argb(128, Color.red(Color.DKGRAY), Color.green(Color.DKGRAY), Color.blue(Color.DKGRAY));
        else
            colorChanged = Color.argb(128, Color.red(Color.LTGRAY), Color.green(Color.LTGRAY), Color.blue(Color.LTGRAY));

        TypedArray ta = context.getTheme().obtainStyledAttributes(new int[]{android.R.attr.textColorPrimary});
        try {
            colorText = ta.getColor(0, 0);
        } finally {
            ta.recycle();
        }

        TypedValue tv = new TypedValue();
        context.getTheme().resolveAttribute(R.attr.colorOn, tv, true);
        colorOn = tv.data;
        context.getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        colorOff = tv.data;

        colorGrayed = ContextCompat.getColor(context, R.color.colorGrayed);

        TypedValue typedValue = new TypedValue();
        context.getTheme().resolveAttribute(android.R.attr.listPreferredItemHeight, typedValue, true);
        int height = TypedValue.complexToDimensionPixelSize(typedValue.data, context.getResources().getDisplayMetrics());
        this.iconSize = Math.round(height * context.getResources().getDisplayMetrics().density + 0.5f);

        setHasStableIds(true);
    }

    public void set(List<Rule> listRule) {
        listAll = listRule;
        listFiltered = new ArrayList<>();
        listFiltered.addAll(listRule);
        notifyDataSetChanged();
    }

    public boolean isLive() {
        return this.live;
    }

    @Override
    public void onAttachedToRecyclerView(RecyclerView recyclerView) {
        super.onAttachedToRecyclerView(recyclerView);
        rv = recyclerView;
    }

    @Override
    public void onDetachedFromRecyclerView(RecyclerView recyclerView) {
        super.onDetachedFromRecyclerView(recyclerView);
        rv = null;
    }

    @Override
    public void onBindViewHolder(final ViewHolder holder, int position) {
        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        // Get rule
        final Rule rule = listFiltered.get(position);

        // Handle expanding/collapsing
        holder.llApplication.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                rule.expanded = !rule.expanded;
                notifyItemChanged(holder.getAdapterPosition());
            }
        });

        // Show if non default rules
        holder.itemView.setBackgroundColor(rule.changed ? colorChanged : Color.TRANSPARENT);

        // Show expand/collapse indicator
        holder.ivExpander.setImageLevel(rule.expanded ? 1 : 0);

        // Show application icon
        if (rule.icon <= 0)
            holder.ivIcon.setImageResource(android.R.drawable.sym_def_app_icon);
        else {
            holder.iconLoader = new IconLoader(holder, rule);
            executor.submit(holder.iconLoader);
        }

        // Show application label
        holder.tvName.setText(rule.name);

        // Show application state
        int color = rule.system ? colorOff : colorText;
        if (!rule.internet || !rule.enabled)
            color = Color.argb(128, Color.red(color), Color.green(color), Color.blue(color));
        holder.tvName.setTextColor(color);

        // Expanded configuration section
        holder.llConfiguration.setVisibility(rule.expanded ? View.VISIBLE : View.GONE);

        // Show application details
        holder.tvUid.setText(Integer.toString(rule.uid));
        holder.tvPackage.setText(rule.packageName);
        holder.tvVersion.setText(rule.version);

        // Show application state
        holder.tvInternet.setVisibility(rule.internet ? View.GONE : View.VISIBLE);
        holder.tvDisabled.setVisibility(rule.enabled ? View.GONE : View.VISIBLE);

        // Show access rules
        if (rule.expanded) {
            // Access the database when expanded only

            final AdapterKeyword adapterKeyword = new AdapterKeyword(context,
                    DatabaseHelper.getInstance(context).getKeywords(rule.uid));

            holder.lvKeywords.setOnItemClickListener(new AdapterView.OnItemClickListener() {
                @Override
                public void onItemClick(AdapterView<?> parent, View view, final int bposition, long bid) {
                    PackageManager pm = context.getPackageManager();
                    Cursor cursor = (Cursor) adapterKeyword.getItem(bposition);

                    final int uid = cursor.getInt(cursor.getColumnIndex("uid"));
                    final String keyword = cursor.getString(cursor.getColumnIndex("keyword"));

                    if (!keyword.equals(context.getResources().getString(R.string.keyword_imei)) &&
                            !keyword.equals(context.getResources().getString(R.string.keyword_phone_number)) &&
                            !keyword.equals(context.getResources().getString(R.string.keyword_imsi)) &&
                            !keyword.equals(context.getResources().getString(R.string.keyword_credit_card))) {

                        PopupMenu popup = new PopupMenu(context, context.findViewById(R.id.vwPopupAnchor));
                        popup.inflate(R.menu.keyword);

                        popup.setOnMenuItemClickListener(new PopupMenu.OnMenuItemClickListener() {
                            @Override
                            public boolean onMenuItemClick(MenuItem menuItem) {
                                int menu = menuItem.getItemId();
                                boolean result = false;
                                switch (menu) {
                                    case R.id.menu_delete:
                                        DatabaseHelper.getInstance(context).deleteKeyword(uid, keyword);
                                        DatabaseHelper.getInstance(context).deleteKeywordFromConnection(uid, keyword);
                                        result = true;
                                        break;
                                }

                                return result;
                            }
                        });

                        popup.show();
                    }
                }
            });
            holder.lvKeywords.setAdapter(adapterKeyword);

            final AdapterConnection adapterConnection = new AdapterConnection(context,
                    DatabaseHelper.getInstance(context).getConnection(rule.uid));

            holder.lvConnections.setOnItemClickListener(new AdapterView.OnItemClickListener() {
                @Override
                public void onItemClick(AdapterView<?> parent, View view, final int bposition, long bid) {
                    PackageManager pm = context.getPackageManager();
                    Cursor cursor = (Cursor) adapterConnection.getItem(bposition);
                    final long id = cursor.getLong(cursor.getColumnIndex("ID"));
                    final String daddr = cursor.getString(cursor.getColumnIndex("daddr"));
                    final int dport = cursor.getInt(cursor.getColumnIndex("dport"));
                    final int version = cursor.getInt(cursor.getColumnIndex("version"));
                    long time = cursor.getLong(cursor.getColumnIndex("time"));
                    int tlsVersion = cursor.getInt(cursor.getColumnIndex("tls_version"));
                    int tlsCompression = cursor.getInt(cursor.getColumnIndex("tls_compression"));
                    final int cipherSuite = cursor.getInt(cursor.getColumnIndex("cipher_suite"));
                    final String cipherSuiteName = cursor.getString(cursor.getColumnIndex("cipher_suite_name"));
                    HashSet<String> tempKeywords = new HashSet<>();

                    Object o = ACNUtils.byteArrayToObject(cursor.getBlob(cursor.getColumnIndex("keywords")));
                    if (o != null && o instanceof HashSet) {
                        tempKeywords = (HashSet<String>) o;
                    }

                    final HashSet<String> keywords = tempKeywords;

                    // secure, insecure colors
                    int colorSecure;
                    int colorInsecure;

                    TypedValue tv = new TypedValue();
                    context.getTheme().resolveAttribute(R.attr.colorOn, tv, true);
                    colorSecure = tv.data;
                    context.getTheme().resolveAttribute(R.attr.colorOff, tv, true);
                    colorInsecure = tv.data;

                    // start building popup menu
                    PopupMenu popup = new PopupMenu(context, context.findViewById(R.id.vwPopupAnchor));
                    popup.inflate(R.menu.connection);

                    popup.getMenu().findItem(R.id.menu_host).setTitle(daddr + (dport > 0 ? "/" + dport : ""));
                    popup.getMenu().findItem(R.id.menu_protocol).setTitle("IPv" + version + " TCP - "
                            + (cipherSuite >= 0 ? "HTTPS (" + ACNUtils.getTLSVersion(tlsVersion) + ")" : "HTTP"));

                    SubMenu sub = popup.getMenu().findItem(R.id.menu_host).getSubMenu();
                    boolean multiple = false;
                    Cursor alt = null;
                    try {
                        alt = DatabaseHelper.getInstance(context).getAlternateQNames(daddr);
                        while (alt.moveToNext()) {
                            multiple = true;
                            sub.add(Menu.NONE, Menu.NONE, 0, alt.getString(0)).setEnabled(false);
                        }
                    } finally {
                        if (alt != null)
                            alt.close();
                    }
                    popup.getMenu().findItem(R.id.menu_host).setEnabled(multiple);

                    // Cipher suite
                    if (cipherSuite >= 0) {
                        SpannableString cipher_suite_menu_title = new SpannableString("Cipher Suite Details");
                        final CipherSuiteLookupTable.Insecurity cipherSuiteInsecurity = CipherSuiteLookupTable.getCipherSuiteInsecurity(cipherSuite);

                        if (cipherSuiteInsecurity == CipherSuiteLookupTable.Insecurity.NONE) {
                            cipher_suite_menu_title.setSpan(new ForegroundColorSpan(colorSecure), 0, cipher_suite_menu_title.length(), 0);
                        } else {
                            cipher_suite_menu_title.setSpan(new ForegroundColorSpan(colorInsecure), 0, cipher_suite_menu_title.length(), 0);
                        }

                        popup.getMenu().findItem(R.id.menu_cipher_suite).setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
                            @Override
                            public boolean onMenuItemClick(MenuItem item) {
                                ACNUtils.cipherSuiteDialog(AdapterSecurity.this.context, R.string.title_cipher_suite_details, cipherSuite, cipherSuiteName, cipherSuiteInsecurity);
                                return true;
                            }
                        });

                        popup.getMenu().findItem(R.id.menu_cipher_suite).setTitle(cipher_suite_menu_title);
                    }

                    // TLS Compression
                    if (tlsCompression != 0) {
                        SpannableString s = new SpannableString("Using Compression (insecure)");
                        s.setSpan(new ForegroundColorSpan(colorInsecure), 0, s.length(), 0);
                        popup.getMenu().findItem(R.id.menu_tls_compression).setTitle(s);
                    } else {
                        SpannableString s = new SpannableString("No Compression (secure)");
                        s.setSpan(new ForegroundColorSpan(colorSecure), 0, s.length(), 0);
                        popup.getMenu().findItem(R.id.menu_tls_compression).setTitle(s);
                    }

                    // Hide Cipher suite menu and tls compression menu when HTTP
                    if (cipherSuite < 0) {
                        popup.getMenu().findItem(R.id.menu_cipher_suite).setVisible(false);
                        popup.getMenu().findItem(R.id.menu_tls_compression).setVisible(false);
                    }

                    // Keywords, colored as insecure because the menu is only shown when any keywords exist in this connection
                    SpannableString keywords_menu_title = new SpannableString("Sensitive Data Details");
                    keywords_menu_title.setSpan(new ForegroundColorSpan(colorInsecure), 0, keywords_menu_title.length(), 0);
                    popup.getMenu().findItem(R.id.menu_keywords).setTitle(keywords_menu_title);
                    popup.getMenu().findItem(R.id.menu_keywords).setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
                        @Override
                        public boolean onMenuItemClick(MenuItem item) {
                            ACNUtils.keywordsDetailsDialog(AdapterSecurity.this.context, new ArrayList<String>(keywords));
                            return true;
                        }
                    });

                    // Hide keywords menu when no keywords in db
                    if (keywords.isEmpty()) {
                        popup.getMenu().findItem(R.id.menu_keywords).setVisible(false);
                    }

                    // Whois
                    final Intent lookupIP = new Intent(Intent.ACTION_VIEW, Uri.parse("https://www.tcpiputils.com/whois-lookup/" + daddr));
                    if (pm.resolveActivity(lookupIP, 0) == null)
                        popup.getMenu().removeItem(R.id.menu_whois);
                    else
                        popup.getMenu().findItem(R.id.menu_whois).setTitle(context.getString(R.string.title_log_whois, daddr));

                    // Lookup port
                    final Intent lookupPort = new Intent(Intent.ACTION_VIEW, Uri.parse("https://www.speedguide.net/port.php?port=" + dport));
                    if (dport <= 0 || pm.resolveActivity(lookupPort, 0) == null)
                        popup.getMenu().removeItem(R.id.menu_port);
                    else
                        popup.getMenu().findItem(R.id.menu_port).setTitle(context.getString(R.string.title_log_port, dport));

                    popup.getMenu().findItem(R.id.menu_time).setTitle(
                            SimpleDateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.MEDIUM, Locale.GERMAN).format(time));

                    popup.setOnMenuItemClickListener(new PopupMenu.OnMenuItemClickListener() {
                        @Override
                        public boolean onMenuItemClick(MenuItem menuItem) {
                            int menu = menuItem.getItemId();
                            boolean result = false;
                            switch (menu) {
                                case R.id.menu_whois:
                                    context.startActivity(lookupIP);
                                    result = true;
                                    break;

                                case R.id.menu_port:
                                    context.startActivity(lookupPort);
                                    result = true;
                                    break;
                            }

                            return result;
                        }
                    });

                    popup.show();
                }
            });

            holder.lvConnections.setAdapter(adapterConnection);
        } else {
            holder.lvKeywords.setAdapter(null);
            holder.lvKeywords.setOnItemClickListener(null);

            holder.lvConnections.setAdapter(null);
            holder.lvConnections.setOnItemClickListener(null);
        }

        // Clear connection log
        holder.btnClearConnections.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Util.areYouSure(view.getContext(), R.string.msg_reset_connections, new Util.DoubtListener() {
                    @Override
                    public void onSure() {
                        DatabaseHelper.getInstance(context).clearConnection(rule.uid);
                        DatabaseHelper.getInstance(context).resetKeywords(rule.uid);
                        if (!live)
                            notifyDataSetChanged();
                        if (rv != null)
                            rv.scrollToPosition(holder.getAdapterPosition());
                    }
                });
            }
        });

        // Add keyword to regex search in http
        holder.btnAddKeyword.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                ACNUtils.keywordInputDialog(view.getContext(), R.string.msg_add_keyword, new ACNUtils.InputListener() {
                    @Override
                    public void onOk(String input, boolean isRegex) {
                        if (!input.isEmpty()) {
                            // add keyword to list
                            DatabaseHelper.getInstance(context).insertKeyword(rule.uid, input, isRegex);
                        }
                    }
                });
            }
        });
    }

    @Override
    public void onViewRecycled(ViewHolder holder) {
        super.onViewRecycled(holder);

        if (holder.iconLoader != null)
            holder.iconLoader.cancel();

        CursorAdapter connectionsAdapter = (CursorAdapter) holder.lvConnections.getAdapter();
        if (connectionsAdapter != null) {
            Log.i(TAG, "Closing connections cursor");
            connectionsAdapter.changeCursor(null);
            holder.lvConnections.setAdapter(null);
        }

        CursorAdapter adapterKeywords = (CursorAdapter) holder.lvKeywords.getAdapter();
        if (adapterKeywords != null) {
            Log.i(TAG, "Closing keywords cursor");
            adapterKeywords.changeCursor(null);
            holder.lvKeywords.setAdapter(null);
        }
    }

    @Override
    public Filter getFilter() {
        return new Filter() {
            @Override
            protected FilterResults performFiltering(CharSequence query) {
                List<Rule> listResult = new ArrayList<>();
                if (query == null)
                    listResult.addAll(listAll);
                else {
                    query = query.toString().toLowerCase().trim();
                    int uid;
                    try {
                        uid = Integer.parseInt(query.toString());
                    } catch (NumberFormatException ignore) {
                        uid = -1;
                    }
                    for (Rule rule : listAll)
                        if (rule.uid == uid ||
                                rule.packageName.toLowerCase().contains(query) ||
                                (rule.name != null && rule.name.toLowerCase().contains(query)))
                            listResult.add(rule);
                }

                FilterResults result = new FilterResults();
                result.values = listResult;
                result.count = listResult.size();
                return result;
            }

            @Override
            protected void publishResults(CharSequence query, FilterResults result) {
                listFiltered.clear();
                if (result == null)
                    listFiltered.addAll(listAll);
                else {
                    listFiltered.addAll((List<Rule>) result.values);
                    if (listFiltered.size() == 1)
                        listFiltered.get(0).expanded = true;
                }
                notifyDataSetChanged();
            }
        };
    }

    @Override
    public AdapterSecurity.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        return new ViewHolder(inflater.inflate(R.layout.security, parent, false));
    }

    @Override
    public long getItemId(int position) {
        Rule rule = listFiltered.get(position);
        return rule.packageName.hashCode() * 100000L + rule.uid;
    }

    @Override
    public int getItemCount() {
        return listFiltered.size();
    }

    private class IconLoader implements Runnable {
        private ViewHolder holder;
        private Rule rule;
        private boolean cancelled = false;

        public IconLoader(ViewHolder holder, Rule rule) {
            this.holder = holder;
            this.rule = rule;
            holder.ivIcon.setHasTransientState(true);
        }

        public void cancel() {
            if (!cancelled)
                Log.i(TAG, "Cancelling icon loader");
            cancelled = true;
        }

        @Override
        public void run() {
            try {
                if (cancelled)
                    throw new InterruptedException();

                Drawable drawable = context.getPackageManager().getApplicationIcon(rule.packageName);
                final Drawable scaledDrawable;
                if (drawable instanceof BitmapDrawable) {
                    Bitmap original = ((BitmapDrawable) drawable).getBitmap();
                    Bitmap scaled = Bitmap.createScaledBitmap(original, iconSize, iconSize, false);
                    scaledDrawable = new BitmapDrawable(context.getResources(), scaled);
                } else
                    scaledDrawable = drawable;

                new Handler(context.getMainLooper()).post(new Runnable() {
                    @Override
                    public void run() {
                        holder.ivIcon.setImageDrawable(scaledDrawable);
                        holder.ivIcon.setHasTransientState(false);
                    }
                });
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                new Handler(context.getMainLooper()).post(new Runnable() {
                    @Override
                    public void run() {
                        holder.ivIcon.setImageDrawable(null);
                        holder.ivIcon.setHasTransientState(false);
                    }
                });
            }
        }
    }
}
