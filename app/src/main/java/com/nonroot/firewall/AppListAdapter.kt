package com.nonroot.firewall

import android.content.Context
import android.graphics.Color
import android.widget.ImageView
import android.graphics.drawable.Drawable
import android.util.LruCache
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView

/** Recycles visible app rows rather than allocating views for every installed package. */
class AppListAdapter(
    private val context: Context,
    private val decision: (String, NetworkKind) -> Decision?,
    private val toggle: (String, NetworkKind) -> Unit,
    private val open: (String) -> Unit
) : RecyclerView.Adapter<AppListAdapter.Holder>() {
    data class Item(val pkg: String, val label: String, val system: Boolean)
    private var items: List<Item> = emptyList()
    private val icons = LruCache<String, Drawable>(96)
    init { setHasStableIds(true) }
    override fun getItemId(position: Int): Long = items[position].pkg.hashCode().toLong()
    fun refreshRule(pkg: String) {
        val position = items.indexOfFirst { it.pkg == pkg }
        if (position >= 0) notifyItemChanged(position)
    }
    fun submit(next: List<Item>) {
        val old = items
        val diff = androidx.recyclerview.widget.DiffUtil.calculateDiff(object : androidx.recyclerview.widget.DiffUtil.Callback() {
            override fun getOldListSize() = old.size
            override fun getNewListSize() = next.size
            override fun areItemsTheSame(o: Int, n: Int) = old[o].pkg == next[n].pkg
            override fun areContentsTheSame(o: Int, n: Int) = old[o] == next[n]
        })
        items = next
        diff.dispatchUpdatesTo(this)
    }
    private fun dp(value: Int) = (value * context.resources.displayMetrics.density + .5f).toInt()
    class Holder(root: LinearLayout, val icon: ImageView, val wifi: TextView, val mobile: TextView, val title: TextView, val subtitle: TextView) : RecyclerView.ViewHolder(root)
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(10), dp(4), dp(10), dp(4))
        }
        fun button() = TextView(context).apply {
            textSize = 23f
            gravity = Gravity.CENTER
        }
        val icon = ImageView(context).apply { scaleType = ImageView.ScaleType.FIT_CENTER; setPadding(dp(4),dp(4),dp(4),dp(4)) }
        row.addView(icon, LinearLayout.LayoutParams(dp(48), dp(48)))
        val wifi = button()
        val mobile = button()
        row.addView(wifi, LinearLayout.LayoutParams(dp(42), dp(48)))
        row.addView(mobile, LinearLayout.LayoutParams(dp(42), dp(48)))
        val labels = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER_VERTICAL }
        val title = TextView(context).apply {
            textSize = 15f; setTextColor(Color.BLACK); maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
        }
        val subtitle = TextView(context).apply {
            textSize = 11f; setTextColor(Color.DKGRAY); maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
        }
        labels.addView(title)
        row.addView(labels, LinearLayout.LayoutParams(0, dp(52), 1f))
        row.addView(TextView(context).apply { text = "›"; textSize = 30f; gravity = Gravity.CENTER; setTextColor(Color.GRAY) }, LinearLayout.LayoutParams(dp(26), dp(52)))
        return Holder(row, icon, wifi, mobile, title, subtitle)
    }
    override fun getItemCount() = items.size
    override fun onBindViewHolder(holder: Holder, position: Int) {
        val item = items[position]
        holder.title.text = item.label
        holder.icon.setImageDrawable(icons.get(item.pkg) ?: try { context.packageManager.getApplicationIcon(item.pkg).also { icons.put(item.pkg, it) } } catch (_: Exception) { context.packageManager.defaultActivityIcon })
        holder.subtitle.text = ""
        fun bind(button: TextView, network: NetworkKind) {
            val value = decision(item.pkg, network)
            button.text = when (value) {
                Decision.ALLOW -> "☑"
                Decision.BLOCK -> "☒"
                else -> "□"
            }
            button.setTextColor(when (value) {
                Decision.ALLOW -> Color.rgb(46, 125, 50)
                Decision.BLOCK -> Color.rgb(198, 40, 40)
                else -> Color.GRAY
            })
            button.contentDescription = "${network}: ${value ?: Decision.PENDING}. Tap to change"
            button.setOnClickListener { toggle(item.pkg, network) }
        }
        bind(holder.wifi, NetworkKind.WIFI)
        bind(holder.mobile, NetworkKind.MOBILE)
        val w = decision(item.pkg, NetworkKind.WIFI)
        val m = decision(item.pkg, NetworkKind.MOBILE)
        holder.itemView.setBackgroundColor(when {
            w == Decision.BLOCK && m == Decision.BLOCK -> Color.rgb(246, 177, 177)
            w == Decision.ALLOW && m == Decision.ALLOW -> Color.rgb(193, 251, 208)
            (w == null || w == Decision.PENDING) && (m == null || m == Decision.PENDING) -> Color.WHITE
            else -> Color.rgb(250, 249, 181)
        })
        holder.itemView.setOnClickListener { open(item.pkg) }
    }
}
