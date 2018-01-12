package at.tugraz.netguard;

import android.content.Context;
import android.database.Cursor;
import android.graphics.Color;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CursorAdapter;
import android.widget.TextView;

import eu.faircode.netguard.R;
import eu.faircode.netguard.Util;

public class AdapterKeyword extends CursorAdapter {
    private int colKeyword;
    private int colOccurred;

    public AdapterKeyword(Context context, Cursor cursor) {
        super(context, cursor, 0);
        colKeyword = cursor.getColumnIndex("keyword");
        colOccurred = cursor.getColumnIndex("occurred");
    }

    @Override
    public View newView(Context context, Cursor cursor, ViewGroup parent) {
        return LayoutInflater.from(context).inflate(R.layout.keyword, parent, false);
    }

    @Override
    public void bindView(final View view, final Context context, final Cursor cursor) {
        // Get values
        String keyword = cursor.getString(colKeyword);
        boolean occurred = cursor.getInt(colOccurred) != 0;

        // Get views
        TextView tvKeyword = view.findViewById(R.id.tvKeyword);
        TextView tvOccurred = view.findViewById(R.id.tvOccurred);

        // Set values
        tvKeyword.setText(keyword);

        // Color occurrences
        if (occurred) {
            tvOccurred.setText(context.getResources().getString(R.string.keyword_detected));
            tvOccurred.setTextColor(Color.RED);
        } else {
            tvOccurred.setText(context.getResources().getString(R.string.keyword_not_detected));
            tvOccurred.setTextColor(Color.GREEN);
        }

        // Highlight hardcoded keywords
        if (keyword.equals(context.getResources().getString(R.string.keyword_imei)) ||
            keyword.equals(context.getResources().getString(R.string.keyword_phone_number))) {

            tvKeyword.setTextColor(Color.MAGENTA);
        }
    }
}
